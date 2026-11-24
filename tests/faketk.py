# Test-only stand-in for tkinter: records widget state and draws canvases with PIL when available. Never imported by the application.
"""Minimal fake tkinter: records widget state, renders Canvas drawing with PIL. For headless testing only."""
import sys, types, itertools
from collections import OrderedDict
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:      # rendering helpers are optional; the scenarios only need widget state
    Image = ImageDraw = ImageFont = None

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

class Var:
    def __init__(self, master=None, value=None, **kw): self.v = value
    def get(self): return self.v
    def set(self, v): self.v = v

class FakeWidget:
    _ids = itertools.count(1)
    def __init__(self, parent=None, *a, **kw):
        self.master = parent; self.kw = dict(kw); self.children = []; self._sel = (); self._items = OrderedDict()
        self.mapped = False; self.path = f".w{next(FakeWidget._ids)}"; self.value = None; self.cmds = []
        if isinstance(parent, FakeWidget): parent.children.append(self)
        self.W = kw.get("width") if isinstance(kw.get("width"), int) else None
        self.H = kw.get("height") if isinstance(kw.get("height"), int) else None
    def __str__(self): return self.path
    def __getattr__(self, name):
        if name.startswith("__"): raise AttributeError(name)
        return lambda *a, **k: None
    def winfo_width(self): return self.W or 600
    def winfo_height(self): return self.H or 100
    def winfo_children(self): return list(self.children)
    def winfo_exists(self): return 1
    def winfo_ismapped(self): return self.mapped
    def winfo_toplevel(self): return self
    def _root(self): return self
    def winfo_y(self): return 0
    def winfo_x(self): return 0
    def pack(self, *a, **k): self.mapped = True
    def grid(self, *a, **k): self.mapped = True
    def pack_forget(self): self.mapped = False
    def destroy(self):
        if isinstance(self.master, FakeWidget) and self in self.master.children: self.master.children.remove(self)
    def configure(self, *a, **kw):
        self.kw.update(kw)
        if "height" in kw and isinstance(kw["height"], int): self.H = kw["height"]
    config = configure
    def cget(self, k): return self.kw.get(k)
    def __setitem__(self, k, v): self.kw[k] = v
    def bind(self, *a, **k): pass
    def state(self, s=None): return ()
    # combobox / entry
    def set(self, a, b=None):
        if b is None: self.value = a; return
        cols = list(self.kw.get("columns", ())); v = self._items[a]["values"][cols.index(b)]; return v
    def get(self): return self.value if self.value is not None else ""
    # treeview
    def insert(self, parent, index, iid=None, values=(), tags=(), text="", open=False, **kw):
        iid = iid or f"I{len(self._items)}"
        self._items[iid] = {"values": tuple(values), "tags": tuple(tags) if not isinstance(tags, str) else (tags,), "parent": parent, "text": text, "open": open}
        return iid
    def delete(self, *ids):
        if isinstance(self, Canvas): return
        for i in ids:
            self._items.pop(i, None)
            for k in [k for k, v in self._items.items() if v.get("parent") == i]: self._items.pop(k, None)
        self._sel = tuple(i for i in self._sel if i in self._items)
    def get_children(self, parent=""):
        return tuple(k for k, v in self._items.items() if v.get("parent", "") == parent)
    def exists(self, iid): return iid in self._items
    def selection(self): return self._sel
    def selection_set(self, ids): self._sel = tuple(ids) if not isinstance(ids, str) else (ids,)
    def yview(self, *a): return (0.0, 1.0)
    def item(self, iid, opt=None, **kw):
        it = self._items[iid]
        return it[opt] if opt else it

class Canvas(FakeWidget):
    def __init__(self, parent=None, *a, **kw):
        super().__init__(parent, *a, **kw); self.ops = []; self.img = None
    def delete(self, *a): self.ops = []
    def _op(self, kind, args, kw): self.ops.append((kind, args, kw)); return len(self.ops)
    def create_line(self, *a, **k): return self._op("line", a, k)
    def create_rectangle(self, *a, **k): return self._op("rect", a, k)
    def create_oval(self, *a, **k): return self._op("oval", a, k)
    def create_arc(self, *a, **k): return self._op("arc", a, k)
    def create_polygon(self, *a, **k): return self._op("poly", a, k)
    def create_text(self, *a, **k): return self._op("text", a, k)
    def create_window(self, *a, **k): return 1
    def itemconfigure(self, *a, **k): pass
    def render(self, W=None, H=None, scale=2):
        W = W or self.winfo_width(); H = H or self.winfo_height()
        img = Image.new("RGB", (W * scale, H * scale), "white"); d = ImageDraw.Draw(img)
        def S(v): return [x * scale for x in v]
        def font(spec):
            fam, size = spec[0], spec[1]; bold = len(spec) > 2 and "bold" in spec[2]
            return ImageFont.truetype(FONTB if bold else FONT, int(size * 1.33 * scale))
        def col(c): return None if c in (None, "") else c
        for kind, a, k in self.ops:
            if kind == "line":
                pts = list(a[0]) if len(a) == 1 else list(a)
                d.line(S(pts), fill=col(k.get("fill")) or "black", width=int(k.get("width", 1) * scale))
            elif kind == "rect":
                d.rectangle(S(a[:4]), fill=col(k.get("fill")), outline=col(k.get("outline")), width=int(k.get("width", 1) * scale) if col(k.get("outline")) else 0)
            elif kind == "oval":
                d.ellipse(S(a[:4]), fill=col(k.get("fill")), outline=col(k.get("outline")))
            elif kind == "poly":
                pts = list(a[0]) if len(a) == 1 else list(a)
                d.polygon(S(pts), fill=col(k.get("fill")), outline=col(k.get("outline")))
            elif kind == "arc":
                s, e = k["start"], k["extent"]; a0, a1 = min(s, s + e), max(s, s + e)
                d.arc(S(a[:4]), start=-a1, end=-a0, fill=k.get("outline"), width=int(k.get("width", 1) * scale))
            elif kind == "text":
                m = {"w": "lm", "e": "rm", "center": "mm", "n": "mt", "s": "ms"}[k.get("anchor", "center")]
                d.text(S(a[:2]), str(k.get("text", "")), font=font(k.get("font", ("x", 9))), fill=k.get("fill", "black"), anchor=m)
        return img

def build():
    tk = types.ModuleType("tkinter")
    ttk = types.ModuleType("tkinter.ttk"); mb = types.ModuleType("tkinter.messagebox"); sd = types.ModuleType("tkinter.simpledialog")
    class TclError(Exception): pass
    tk.TclError = TclError; tk.StringVar = type("StringVar", (Var,), {"__init__": lambda self, master=None, value="", **kw: setattr(self, "v", value)})
    tk.BooleanVar = type("BooleanVar", (Var,), {"__init__": lambda self, master=None, value=False, **kw: setattr(self, "v", value)})
    tk.IntVar = tk.DoubleVar = tk.StringVar; tk.Canvas = Canvas
    tk.TkVersion = 8.6
    for n in ("Frame", "Label", "Toplevel", "Tk", "Text", "Listbox", "Button", "Entry", "Scrollbar", "Menu", "PhotoImage", "Widget"):
        setattr(tk, n, type(n, (FakeWidget,), {}))
    def mod_getattr(m):
        def g(name):
            if name.startswith("__"): raise AttributeError(name)
            if name.isupper(): return name.lower()
            if name[0].isupper(): return type(name, (FakeWidget,), {})
            return lambda *a, **k: None
        m.__getattr__ = g
    for m in (tk, ttk, mb, sd): mod_getattr(m)
    tk.ttk, tk.messagebox, tk.simpledialog = ttk, mb, sd
    sys.modules.update({"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.simpledialog": sd})
    return tk
