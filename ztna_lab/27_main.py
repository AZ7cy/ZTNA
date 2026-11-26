# Part 27 of ztna.py - command-line entry point main().
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

def main(argv=None):
    global REQUESTED_MODE, DEMO
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["gui"]
    if argv[0] in {"-h", "--help"}:
        print(USAGE)
        return 0

    mode = argv[0].lower()
    mode = "enterprise" if mode == "api" else mode
    if mode not in VALID_MODES:
        print(USAGE)
        return 2

    REQUESTED_MODE = mode
    _configure_logging()
    if mode == "probe":
        return run_probe(argv[1:])
    if mode == "dns":
        return run_dns_cli(argv[1:])
    if mode == "cli":
        return run_admin_cli(argv[1:])
    if mode == "systemd":
        return print_systemd_unit(argv[1:])

    # GUI checks happen before init_runtime(): a missing Tk package or display
    # must not create databases, audit files, or other persistent state.
    if mode == "gui":
        if ttk is None or messagebox is None:
            raise SystemExit("tkinter is not available (install python3-tk)")

        # The desktop entry point opens the integrated GUI directly. This GUI
        # is local-only and does not start an HTTP listener. Production users can
        # explicitly set ZTNA_DEMO=0 and configure their provisioned user store.
        os.environ.setdefault("ZTNA_DEMO", "1")
        if os.environ.get("ZTNA_DEMO") == "1":
            os.environ.setdefault("ZTNA_DEMO_OTP", "1")
            # Demo accounts are provisioned with encrypted TOTP secrets. Say so up front instead of failing with a
            # traceback after the credentials were generated (the launcher then blamed Python/Tkinter).
            if not _cryptography_available():
                raise SystemExit(f"The desktop GUI cannot start: {CRYPTOGRAPHY_MISSING}")

    init_runtime(mode)

    if mode == "gui" and DEMO:
        logger.warning("LOCAL DEMO MODE enabled: preset lab credentials are active")
        if DEMO_OTP:
            logger.warning(
                "DEMO OTP GENERATOR enabled: use only for an isolated local lab"
            )

    if mode == "adduser":
        add_user_cli(argv[1:])
    elif mode == "enterprise":
        run_enterprise_api()
    elif mode == "gui":
        try:
            app = App()
        except tk.TclError as exc:
            raise SystemExit(
                f"cannot open a display for the GUI: {exc}"
            ) from None
        app.mainloop()
    elif mode == "server":
        run_legacy_server()
    elif mode == "attack":
        ok = attack(
            argv[1] if len(argv) > 1
            else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        )
        return 0 if ok else 1
    elif mode == "bench":
        bench(
            argv[1] if len(argv) > 1
            else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        )
    elif mode == "agent":
        if len(argv) < 3:
            raise SystemExit("usage: agent DEVICE key=value ... [URL]")
        has_url = argv[-1].startswith(("http://", "https://"))
        base = argv[-1] if has_url else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        kv = argv[2:-1] if has_url else argv[2:]
        return 0 if agent(argv[1], kv, base) else 1
    elif mode == "iptables":
        print("\n".join(firewall_rules()))
    elif mode == "compose":
        out = Path(os.environ.get("ZTNA_COMPOSE_FILE", "docker-compose.yml"))
        if out.exists() and os.environ.get("ZTNA_COMPOSE_FORCE") != "1":
            raise SystemExit(
                f"{out} exists; set ZTNA_COMPOSE_FORCE=1 to overwrite"
            )
        out.write_text(
            COMPOSE.replace("%SCRIPT%", os.path.basename(__file__)),
            encoding="utf-8",
        )
        print(out)
    elif mode == "verify":
        result = verify_chain()
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    elif mode == "selftest":
        return 0 if selftest() else 1
    return 0
