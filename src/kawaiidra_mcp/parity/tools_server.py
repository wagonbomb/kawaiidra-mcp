"""Phase 17 — Ghidra Server, version control and repository administration.

Connection settings come from the session (server_connect / server_authenticate)
or the environment: GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT (default 13100),
GHIDRA_SERVER_USER, GHIDRA_SERVER_PASSWORD. They are handed to Ghidra
subprocesses as environment variables, never written into script files.

Version-control tools act on files of a *shared* kawaiidra project: share one
with server_share_project (converts a local project to use a repository).
"""

from __future__ import annotations

import os

from .framework import EXTRA_ENV, JTool, execute, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


_SERVER = '''
from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator
from ghidra.framework.remote import User

def _env(k, d=None):
    v = os.environ.get("KAWAIIDRA_" + k) or os.environ.get(k)
    return v if v else d

def server():
    host = _env("GHIDRA_SERVER_HOST")
    if not host:
        raise Fail("No Ghidra Server configured: call server_connect (or set GHIDRA_SERVER_HOST)")
    port = int(_env("GHIDRA_SERVER_PORT", "13100"))
    user = _env("GHIDRA_SERVER_USER")
    if user:
        ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(user, _env("GHIDRA_SERVER_PASSWORD", "")))
    rsa = ClientUtil.getRepositoryServer(host, port, True)
    if rsa is None or not rsa.isConnected():
        err = None
        try:
            err = rsa.getLastConnectError() if rsa is not None else None
        except (Exception, Throwable):
            pass
        raise Fail("Cannot connect to Ghidra Server %s:%d %s" % (host, port, _s(err) if err else ""))
    return rsa

def repo(name):
    r = server().getRepository(name)
    if r is None:
        raise Fail("Repository not found: " + _s(name))
    r.connect()
    return r

def split_item(path):
    path = _s(path)
    if not path.startswith("/"):
        path = "/" + path
    folder, _, item = path.rpartition("/")
    return (folder or "/"), item

def item_path(folder, name):
    return folder.rstrip("/") + "/" + _s(name)

def item_info(it, folder="/"):
    return {"name": _s(it.getName()), "path": item_path(folder, it.getName()), "version": it.getVersion(),
            "content_type": _s(it.getContentType())}

def checkout_info(c):
    return {"checkout_id": c.getCheckoutId(), "user": _s(c.getUser()), "version": c.getCheckoutVersion(),
            "time": c.getCheckoutTime(), "exclusive": _s(c.getCheckoutType()),
            "project": _s(c.getProjectPath()) if hasattr(c, "getProjectPath") else None}

def shared_file(path):
    server()  # installs the authenticator before the shared project reconnects
    gp = open_project()
    pd = gp.getProjectData()
    if pd.getRepository() is None:
        raise Fail("Project '%s' is not shared; use server_share_project first" % ARGS.get("project_name"))
    return gp, find_domain_file(gp, path)

PERMS = {"none": -1, "read": User.READ_ONLY, "read_only": User.READ_ONLY,
         "write": User.WRITE, "admin": User.ADMIN}
'''


def _session_connect(args: dict) -> dict:
    host = args.get("host") or os.environ.get("GHIDRA_SERVER_HOST")
    if not host:
        return {"error": "host is required (or set GHIDRA_SERVER_HOST)"}
    EXTRA_ENV["KAWAIIDRA_GHIDRA_SERVER_HOST"] = str(host)
    EXTRA_ENV["KAWAIIDRA_GHIDRA_SERVER_PORT"] = str(args.get("port") or os.environ.get("GHIDRA_SERVER_PORT") or 13100)
    res = execute(_STATUS, {"project_name": args.get("project_name") or "default"})
    if res.get("error"):
        return res
    res["success"] = True
    return res


def _session_auth(args: dict) -> dict:
    if not args.get("username"):
        return {"error": "username is required"}
    EXTRA_ENV["KAWAIIDRA_GHIDRA_SERVER_USER"] = args["username"]
    EXTRA_ENV["KAWAIIDRA_GHIDRA_SERVER_PASSWORD"] = args.get("password") or ""
    return {"success": True, "username": args["username"],
            "note": "Credentials kept in server memory for this session only and passed to Ghidra via environment."}


def _session_disconnect(args: dict) -> dict:
    for k in list(EXTRA_ENV):
        if k.startswith("KAWAIIDRA_GHIDRA_SERVER_"):
            del EXTRA_ENV[k]
    return {"success": True, "connected": False}


_STATUS = JTool(
    name="server_status",
    description="Check the Ghidra Server connection: host, port, connected user, server info, anonymous access and repository count.",
    mode="project",
    helpers=_SERVER,
    body='''
    rsa = server()
    names = list(rsa.getRepositoryNames())
    return {"connected": rsa.isConnected(), "host": _env("GHIDRA_SERVER_HOST"),
            "port": int(_env("GHIDRA_SERVER_PORT", "13100")), "user": _s(rsa.getUser()),
            "server_info": _s(rsa.getServerInfo()), "anonymous_access_allowed": rsa.anonymousAccessAllowed(),
            "repository_count": len(names)}
    ''',
)

register(
    JTool(name="server_connect", mode="local", local=_session_connect,
          description="Set the Ghidra Server for this session (host/port) and verify the connection. Authenticate first with server_authenticate if the server needs a password.",
          properties={"host": _p("Server host (default GHIDRA_SERVER_HOST)"), "port": _p("Port (default 13100)", I)}),
    JTool(name="server_authenticate", mode="local", local=_session_auth,
          description="Register Ghidra Server credentials for programmatic (password-mode) authentication in this session.",
          properties={"username": _p("User name"), "password": _p("Password")},
          required=["username"]),
    JTool(name="server_disconnect", mode="local", local=_session_disconnect,
          description="Forget the session's Ghidra Server connection and credentials."),
    _STATUS,
    JTool(
        name="server_repositories",
        description="List repositories on the connected Ghidra Server.",
        mode="project",
        helpers=_SERVER,
        body='''
        return {"repositories": [_s(n) for n in server().getRepositoryNames()]}
        ''',
    ),
    JTool(
        name="server_repository_create",
        description="Create a new repository on the Ghidra Server.",
        properties={"name": _p("Repository name")},
        required=["name"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = server().createRepository(arg("name"))
        return {"success": True, "repository": _s(r.getName())}
        ''',
    ),
    JTool(
        name="server_repository_files",
        description="List files and subfolders in a repository folder.",
        properties={"repo": _p("Repository"), "path": _p("Folder path (default /)")},
        required=["repo"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        path = arg("path", "/")
        return {"repository": arg("repo"), "path": path,
                "folders": [_s(f) for f in r.getSubfolderList(path)],
                "files": [item_info(i, path) for i in r.getItemList(path)]}
        ''',
    ),
    JTool(
        name="server_repository_file",
        description="Get details of one repository file: current version, version history and checkouts.",
        properties={"repo": _p("Repository"), "path": _p("File path, e.g. /putty.exe")},
        required=["repo", "path"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        folder, name = split_item(arg("path"))
        it = r.getItem(folder, name)
        if it is None:
            raise Fail("File not found: " + arg("path"))
        info = item_info(it, folder)
        info["versions"] = [{"version": v.getVersion(), "user": _s(v.getUser()), "comment": _s(v.getComment()),
                             "time": v.getCreateTime()} for v in r.getVersions(folder, name)]
        info["checkouts"] = [checkout_info(c) for c in r.getCheckouts(folder, name)]
        return info
        ''',
    ),
    JTool(
        name="server_checkouts",
        description="List checkouts (all users) for files in a repository folder, recursively.",
        properties={"repo": _p("Repository"), "path": _p("Folder path (default /)")},
        required=["repo"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        out = []
        stack = [arg("path", "/")]
        while stack:
            folder = stack.pop()
            for it in r.getItemList(folder):
                for c in r.getCheckouts(folder, it.getName()):
                    d = checkout_info(c); d["file"] = item_path(folder, it.getName()); out.append(d)
            for sub in r.getSubfolderList(folder):
                stack.append((folder.rstrip("/") + "/" + sub))
        return {"repository": arg("repo"), "checkouts": out, "count": len(out)}
        ''',
    ),
    JTool(
        name="server_admin_users",
        description="List all users known to the Ghidra Server (admin view).",
        mode="project",
        helpers=_SERVER,
        body='''
        return {"users": [_s(u) for u in server().getAllUsers()]}
        ''',
    ),
    JTool(
        name="server_admin_set_permissions",
        description="Set a user's access on a repository: read, write, admin or none (removes the user). Requires repository admin.",
        properties={"repo": _p("Repository"), "user": _p("User name"),
                    "access_level": _p("read | write | admin | none", enum=["read", "write", "admin", "none"])},
        required=["repo", "user", "access_level"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        level = PERMS.get(arg("access_level").lower())
        if level is None:
            raise Fail("access_level must be read, write, admin or none")
        users = [u for u in r.getUserList() if u.getName() != arg("user")]
        if level >= 0:
            users.append(User(arg("user"), level))
        r.setUserList(users, r.anonymousAccessAllowed())
        return {"success": True, "repository": arg("repo"),
                "users": [{"name": _s(u.getName()), "admin": u.isAdmin(), "write": u.hasWritePermission()} for u in r.getUserList()]}
        ''',
    ),
    JTool(
        name="server_admin_terminate_checkout",
        description="Terminate checkouts on one repository file (all, or one checkout_id). Requires admin or ownership.",
        properties={"repo": _p("Repository"), "path": _p("File path"), "checkout_id": _p("Only this checkout", I)},
        required=["repo", "path"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        folder, name = split_item(arg("path"))
        done = []
        for c in r.getCheckouts(folder, name):
            if arg("checkout_id") is not None and c.getCheckoutId() != int(arg("checkout_id")):
                continue
            r.terminateCheckout(folder, name, c.getCheckoutId(), False)
            done.append(c.getCheckoutId())
        return {"success": True, "terminated": done}
        ''',
    ),
    JTool(
        name="server_admin_terminate_all_checkouts",
        description="Terminate every checkout under a repository folder, recursively.",
        properties={"repo": _p("Repository"), "path": _p("Folder path (default /)")},
        required=["repo"],
        mode="project",
        helpers=_SERVER,
        body='''
        r = repo(arg("repo"))
        done = []
        stack = [arg("path", "/")]
        while stack:
            folder = stack.pop()
            for it in r.getItemList(folder):
                for c in r.getCheckouts(folder, it.getName()):
                    r.terminateCheckout(folder, it.getName(), c.getCheckoutId(), False)
                    done.append({"file": item_path(folder, it.getName()), "checkout_id": c.getCheckoutId()})
            for sub in r.getSubfolderList(folder):
                stack.append(folder.rstrip("/") + "/" + sub)
        return {"success": True, "terminated": done, "count": len(done)}
        ''',
    ),
    JTool(
        name="server_share_project",
        description="Convert a local kawaiidra project into a shared project backed by a Ghidra Server repository (required before version-control tools).",
        properties={"repo": _p("Repository (created if missing)")},
        required=["repo"],
        mode="project",
        timeout=1800,
        helpers=_SERVER,
        body='''
        rsa = server()
        if arg("repo") not in [_s(n) for n in rsa.getRepositoryNames()]:
            rsa.createRepository(arg("repo"))
        r = rsa.getRepository(arg("repo"))
        r.connect()
        gp = open_project()
        pd = gp.getProjectData()
        if pd.getRepository() is not None:
            return {"success": True, "already_shared": True, "repository": _s(pd.getRepository().getName())}
        pd.convertProjectToShared(r, MONITOR)
        return {"success": True, "project": ARGS.get("project_name"), "repository": arg("repo")}
        ''',
    ),
    JTool(
        name="server_version_control_add",
        description="Add a project file to version control (shared project).",
        properties={"path": _p("File name or /path"), "comment": _p("Version comment"),
                    "keep_checked_out": _p("Keep it checked out (default false)", B)},
        required=["path"],
        mode="project",
        timeout=1800,
        helpers=_SERVER,
        body='''
        gp, df = shared_file(arg("path"))
        if df.isVersioned():
            raise Fail("Already under version control: " + _s(df.getPathname()))
        df.addToVersionControl(arg("comment", "Added by kawaiidra"), arg_bool("keep_checked_out"), MONITOR)
        return {"success": True, "path": _s(df.getPathname()), "version": df.getLatestVersion(),
                "checked_out": df.isCheckedOut()}
        ''',
    ),
    JTool(
        name="server_version_control_checkout",
        description="Check out a version-controlled project file (exclusive optional).",
        properties={"path": _p("File name or /path"), "exclusive": _p("Exclusive checkout (default false)", B)},
        required=["path"],
        mode="project",
        timeout=1800,
        helpers=_SERVER,
        body='''
        gp, df = shared_file(arg("path"))
        if df.isCheckedOut():
            return {"success": True, "already_checked_out": True, "path": _s(df.getPathname())}
        ok = df.checkout(arg_bool("exclusive"), MONITOR)
        return {"success": bool(ok), "path": _s(df.getPathname()), "checked_out": df.isCheckedOut(),
                "exclusive": df.isCheckedOutExclusive()}
        ''',
    ),
    JTool(
        name="server_version_control_undo_checkout",
        description="Undo a checkout (keep=true saves local changes to a .keep copy).",
        properties={"path": _p("File name or /path"), "keep": _p("Keep a private copy (default false)", B)},
        required=["path"],
        mode="project",
        helpers=_SERVER,
        body='''
        gp, df = shared_file(arg("path"))
        if not df.isCheckedOut():
            raise Fail("Not checked out: " + _s(df.getPathname()))
        df.undoCheckout(arg_bool("keep"))
        return {"success": True, "path": _s(df.getPathname()), "checked_out": df.isCheckedOut()}
        ''',
    ),
    JTool(
        name="checkin_program",
        description="Check a checked-out program back in to the Ghidra Server as a new version (dry_run reports what would be checked in).",
        properties={"path": _p("File name or /path"), "comment": _p("Version comment"),
                    "keep_checked_out": _p("Keep checked out after check-in (default false)", B),
                    "dry_run": _p("Report only (default false)", B)},
        required=["path"],
        mode="project",
        timeout=1800,
        helpers=_SERVER,
        body='''
        from ghidra.framework.data import CheckinHandler
        gp, df = shared_file(arg("path"))
        if not df.isCheckedOut():
            raise Fail("Not checked out: " + _s(df.getPathname()))
        info = {"path": _s(df.getPathname()), "modified_since_checkout": df.modifiedSinceCheckout(),
                "current_version": df.getLatestVersion()}
        if arg_bool("dry_run"):
            info["dry_run"] = True
            return info
        class H(CheckinHandler):
            def getComment(self): return arg("comment", "Checked in by kawaiidra")
            def keepCheckedOut(self): return arg_bool("keep_checked_out")
            def createKeepFile(self): return False
        df.checkin(H(), MONITOR)
        info.update({"success": True, "new_version": df.getLatestVersion(), "checked_out": df.isCheckedOut()})
        return info
        ''',
    ),
    JTool(
        name="server_version_history",
        description="Version history of a version-controlled project file.",
        properties={"path": _p("File name or /path")},
        required=["path"],
        mode="project",
        helpers=_SERVER,
        body='''
        gp, df = shared_file(arg("path"))
        hist = df.getVersionHistory()
        return {"path": _s(df.getPathname()), "versions": [
            {"version": v.getVersion(), "user": _s(v.getUser()), "comment": _s(v.getComment()),
             "time": v.getCreateTime()} for v in (hist or [])]}
        ''',
    ),
)
