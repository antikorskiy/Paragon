import getpass
import os
import queue
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog

from core import (Core, Peer, decode_id, encode_id, fmt_size,
                  generate_identity, generate_onion_identity, is_onion,
                  peer_key_from_id, write_hidden_service_dir)


class FileOfferDialog:
    def __init__(self, parent, peer_name, name, size, on_accept, on_decline):
        self.on_accept = on_accept
        self.on_decline = on_decline
        self.win = tk.Toplevel(parent)
        self.win.title(f"Incoming file from {peer_name}")
        self.win.configure(bg="#1e1e1e")
        self.win.geometry("420x220")
        self.win.transient(parent)
        self.win.protocol("WM_DELETE_WINDOW", self._decline)
        tk.Label(self.win, text=f"{peer_name} wants to send:",
                 bg="#1e1e1e", fg="#888", font=("Menlo", 10)).pack(pady=(16, 4))
        tk.Label(self.win, text=name, bg="#1e1e1e", fg="#e0e0e0",
                 font=("Menlo", 12, "bold"), wraplength=380).pack(pady=4)
        tk.Label(self.win, text=fmt_size(size), bg="#1e1e1e", fg="#888",
                 font=("Menlo", 10)).pack(pady=(0, 16))
        row = tk.Frame(self.win, bg="#1e1e1e")
        row.pack()
        tk.Button(row, text="Accept", command=self._accept, bg="#4caf50",
                  fg="white", font=("Menlo", 10, "bold"), relief="flat",
                  width=12, activebackground="#66bb6a").pack(side="left", padx=6, ipady=6)
        tk.Button(row, text="Decline", command=self._decline, bg="#f44336",
                  fg="white", font=("Menlo", 10), relief="flat",
                  width=12, activebackground="#e57373").pack(side="left", padx=6, ipady=6)
        try:
            self.win.grab_set()
        except Exception:
            pass
    def _accept(self):
        self.on_accept()
        self.win.destroy()
    def _decline(self):
        self.on_decline()
        self.win.destroy()


class AddContactDialog:
    def __init__(self, parent):
        self.result = None
        self.win = tk.Toplevel(parent)
        self.win.title("Add contact")
        self.win.configure(bg="#1e1e1e")
        self.win.geometry("520x260")
        self.win.transient(parent)
        P = dict(padx=14)
        tk.Label(self.win, text="ADD CONTACT", bg="#1e1e1e", fg="#a0e0a0",
                 font=("Menlo", 11, "bold")).pack(anchor="w", **P, pady=(14, 4))
        tk.Label(self.win, text="Paste peer's base64 ID:",
                 bg="#1e1e1e", fg="#aaa", font=("Menlo", 9)).pack(anchor="w", **P)
        self.id_entry = tk.Entry(self.win, bg="#333", fg="white",
                                 font=("Menlo", 10), insertbackground="white",
                                 relief="flat")
        self.id_entry.pack(fill="x", **P, pady=(0, 8), ipady=4)
        tk.Label(self.win, text="Display name (optional):",
                 bg="#1e1e1e", fg="#aaa", font=("Menlo", 9)).pack(anchor="w", **P)
        self.name_entry = tk.Entry(self.win, bg="#333", fg="white",
                                   font=("Menlo", 10), insertbackground="white",
                                   relief="flat")
        self.name_entry.pack(fill="x", **P, pady=(0, 10), ipady=4)
        self.error = tk.Label(self.win, text="", bg="#1e1e1e", fg="#f44336",
                              font=("Menlo", 9), wraplength=480, justify="left")
        self.error.pack(anchor="w", **P)
        tk.Button(self.win, text="ADD", command=self._submit, bg="#4caf50",
                  fg="white", font=("Menlo", 11, "bold"), relief="flat",
                  activebackground="#66bb6a").pack(fill="x", **P, pady=(4, 14), ipady=6)
        try:
            self.win.grab_set()
        except Exception:
            pass
        parent.wait_window(self.win)
    def _submit(self):
        id_str = self.id_entry.get().strip()
        if not id_str:
            self.error.config(text="ID required")
            return
        try:
            decode_id(id_str)
        except ValueError as e:
            self.error.config(text=f"{e}")
            return
        self.result = (id_str, self.name_entry.get().strip())
        self.win.destroy()


class SettingsDialog:
    def __init__(self, parent, core, on_save):
        self.core = core
        self.on_save = on_save
        self.win = tk.Toplevel(parent)
        self.win.title("Settings")
        self.win.configure(bg="#1e1e1e")
        self.win.geometry("520x480")
        self.win.transient(parent)
        P = dict(padx=14)
        tk.Label(self.win, text="SETTINGS", bg="#1e1e1e", fg="#7fb3ff",
                 font=("Menlo", 11, "bold")).pack(anchor="w", **P, pady=(14, 4))
        tk.Label(self.win, text="Delay min (s):", bg="#1e1e1e", fg="#aaa",
                 font=("Menlo", 9)).pack(anchor="w", **P)
        self.dmin = tk.Entry(self.win, bg="#333", fg="white", font=("Menlo", 10),
                             insertbackground="white", relief="flat")
        self.dmin.insert(0, str(core.delay_min))
        self.dmin.pack(fill="x", **P, pady=(0, 6), ipady=4)
        tk.Label(self.win, text="Delay max (s):", bg="#1e1e1e", fg="#aaa",
                 font=("Menlo", 9)).pack(anchor="w", **P)
        self.dmax = tk.Entry(self.win, bg="#333", fg="white", font=("Menlo", 10),
                             insertbackground="white", relief="flat")
        self.dmax.insert(0, str(core.delay_max))
        self.dmax.pack(fill="x", **P, pady=(0, 6), ipady=4)
        tk.Label(self.win, text="Ping interval (s):", bg="#1e1e1e", fg="#aaa",
                 font=("Menlo", 9)).pack(anchor="w", **P)
        self.ping = tk.Entry(self.win, bg="#333", fg="white", font=("Menlo", 10),
                             insertbackground="white", relief="flat")
        self.ping.insert(0, str(core.ping_interval))
        self.ping.pack(fill="x", **P, pady=(0, 10), ipady=4)
        self.error = tk.Label(self.win, text="", bg="#1e1e1e", fg="#f44336",
                              font=("Menlo", 9), wraplength=480, justify="left")
        self.error.pack(anchor="w", **P)
        tk.Button(self.win, text="SAVE SETTINGS", command=self._save,
                  bg="#4caf50", fg="white", font=("Menlo", 10, "bold"),
                  relief="flat", activebackground="#66bb6a").pack(
                      fill="x", **P, pady=(4, 14), ipady=6)
        tk.Label(self.win, text="MY IDENTITY", bg="#1e1e1e", fg="#ffb300",
                 font=("Menlo", 11, "bold")).pack(anchor="w", **P, pady=(4, 4))
        tk.Label(self.win, text="Current ID:", bg="#1e1e1e", fg="#aaa",
                 font=("Menlo", 9)).pack(anchor="w", **P)
        self.id_label = tk.Label(self.win, text=core.my_id_str or "?",
                                 bg="#1e1e1e", fg="#a0e0a0", font=("Menlo", 8),
                                 wraplength=480, justify="left")
        self.id_label.pack(anchor="w", **P, pady=(0, 6))
        row = tk.Frame(self.win, bg="#1e1e1e")
        row.pack(fill="x", **P, pady=(0, 6))
        tk.Button(row, text="Copy ID", command=self._copy_id, bg="#444",
                  fg="white", font=("Menlo", 9), relief="flat",
                  activebackground="#555").pack(side="left", ipady=3, ipadx=8)
        tk.Button(row, text="Regenerate token", command=self._regen,
                  bg="#f44336", fg="white", font=("Menlo", 9), relief="flat",
                  activebackground="#e57373").pack(side="left", padx=(6, 0),
                                                  ipady=3, ipadx=8)
        tk.Label(self.win,
                 text="Regenerate = new identity. All current contacts will break "
                      "and must be re-added.",
                 bg="#1e1e1e", fg="#666", font=("Menlo", 8, "italic"),
                 wraplength=480, justify="left").pack(anchor="w", **P, pady=(4, 8))
        try:
            self.win.grab_set()
        except Exception:
            pass
    def _save(self):
        try:
            dmin = float(self.dmin.get() or 0)
            dmax = float(self.dmax.get() or 0)
            ping = float(self.ping.get() or 30)
        except ValueError:
            self.error.config(text="Numbers expected")
            return
        self.on_save(dmin, dmax, ping)
        self.win.destroy()
    def _copy_id(self):
        try:
            self.win.clipboard_clear()
            self.win.clipboard_append(self.core.my_id_str or "")
        except Exception:
            pass
    def _regen(self):
        if not messagebox.askyesno(
                "Regenerate token",
                "This will create a NEW identity.\n\n"
                "All current contacts will no longer be able to reach you, "
                "and you will appear to them as a new (unknown) contact.\n\n"
                "Continue?",
                parent=self.win):
            return
        self.core.regenerate_token()
        self.id_label.config(text=self.core.my_id_str or "?")


class ChatUI:
    POLL_MS = 40
    def __init__(self, root, core):
        self.root = root
        self.core = core
        self.events = core.events
        self.current_peer_key = None
        self._file_names = {}
        self._peer_status = {}
        self._peer_icons = {}
        root.title("Paragon Chat")
        root.geometry("960x640")
        root.configure(bg="#1e1e1e")
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        main = tk.Frame(root, bg="#1e1e1e")
        main.pack(fill="both", expand=True)
        sidebar = tk.Frame(main, bg="#181818", width=260)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        top = tk.Frame(sidebar, bg="#181818")
        top.pack(fill="x", padx=8, pady=(8, 4))
        tk.Button(top, text="+ Add", command=self.on_add_contact, bg="#444",
                  fg="white", font=("Menlo", 9), relief="flat",
                  activebackground="#555").pack(side="left", ipady=3, ipadx=6)
        tk.Button(top, text="⚙", command=self.on_settings, bg="#444",
                  fg="white", font=("Menlo", 9), relief="flat",
                  activebackground="#555", width=3).pack(side="right", ipady=3)
        self.peer_list = tk.Listbox(sidebar, bg="#181818", fg="#e0e0e0",
                                    font=("Menlo", 10), relief="flat",
                                    highlightthickness=0, activestyle="none",
                                    selectbackground="#2a4a6a",
                                    selectforeground="white")
        self.peer_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.peer_list.bind("<<ListboxSelect>>", self.on_peer_selected)
        self.peer_list.bind("<Button-3>", self.on_peer_menu)
        self.menu = tk.Menu(root, tearoff=0, bg="#2a2a2a", fg="white",
                            activebackground="#444", activeforeground="white")
        self.menu.add_command(label="Rename", command=self.on_rename_peer)
        self.menu.add_command(label="Remove", command=self.on_remove_peer)
        right = tk.Frame(main, bg="#1e1e1e")
        right.pack(side="left", fill="both", expand=True)
        self.status = tk.Label(right, text="No contact selected",
                               bg="#1e1e1e", fg="#888", anchor="w",
                               font=("Menlo", 10), padx=12, pady=6)
        self.status.pack(fill="x")
        self.chat = scrolledtext.ScrolledText(
            right, bg="#252526", fg="#e0e0e0", font=("Menlo", 11),
            wrap="word", state="disabled", padx=12, pady=12,
            insertbackground="white", relief="flat", borderwidth=0)
        self.chat.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.chat.tag_configure("me", foreground="#7fb3ff", justify="right")
        self.chat.tag_configure("peer", foreground="#a0e0a0", justify="left")
        self.chat.tag_configure("sys", foreground="#c09040",
                                font=("Menlo", 9, "italic"), justify="center")
        bottom = tk.Frame(right, bg="#1e1e1e")
        bottom.pack(fill="x", padx=12, pady=(0, 12))
        self.attach_btn = tk.Button(bottom, text="📎", command=self.on_attach,
                                    bg="#333", fg="white", font=("Menlo", 11),
                                    relief="flat", activebackground="#555",
                                    width=3, state="disabled")
        self.attach_btn.pack(side="left", padx=(0, 6), ipady=4)
        self.input = tk.Entry(bottom, bg="#333", fg="white", font=("Menlo", 11),
                              insertbackground="white", relief="flat",
                              state="disabled")
        self.input.pack(side="left", fill="x", expand=True, ipady=8)
        self.input.bind("<Return>", self.on_send)
        self._refresh_peer_list()
        root.after(self.POLL_MS, self.poll_events)

    def _refresh_peer_list(self):
        sel_key = self.current_peer_key
        self.peer_list.delete(0, "end")
        self._peer_icons.clear()
        peers = sorted(self.core.get_peers(),
                       key=lambda p: (p.name or p.peer_key).lower())
        sel_idx = -1
        for i, p in enumerate(peers):
            name = p.name or "(unnamed)"
            icon = "●" if p.peer_key in self._peer_status else "○"
            self._peer_icons[p.peer_key] = icon
            self.peer_list.insert("end", f" {icon}  {name}")
            self.peer_list.itemconfig(i, foreground="#e0e0e0")
            if p.peer_key == sel_key:
                sel_idx = i
        if sel_idx >= 0:
            self.peer_list.selection_set(sel_idx)

    def _peer_by_key(self, peer_key):
        for p in self.core.get_peers():
            if p.peer_key == peer_key:
                return p
        return None

    def _peer_display(self, peer_key):
        p = self._peer_by_key(peer_key)
        if not p:
            return peer_key
        return p.name or p.peer_key[:8]

    def on_peer_selected(self, _evt=None):
        sel = self.peer_list.curselection()
        if not sel:
            return
        peers = sorted(self.core.get_peers(),
                       key=lambda p: (p.name or p.peer_key).lower())
        if sel[0] >= len(peers):
            return
        pk = peers[sel[0]].peer_key
        if pk == self.current_peer_key:
            return
        self.current_peer_key = pk
        self.input.config(state="normal")
        self.attach_btn.config(state="normal")
        self._render_chat()

    def _render_chat(self):
        self.chat.configure(state="normal")
        self.chat.delete("1.0", "end")
        self.chat.configure(state="disabled")
        pk = self.current_peer_key
        if not pk:
            self.status.config(text="No contact selected", fg="#888")
            return
        name = self._peer_display(pk)
        online = pk in self._peer_status
        self.status.config(
            text=f"{'● online' if online else '○ offline'}  —  {name}",
            fg="#4caf50" if online else "#888")
        for item in self.core.get_history(pk):
            if item["kind"] == "in":
                self._append(f"peer: {item['text']}", "peer")
            elif item["kind"] == "out":
                mid = item.get("id", "")
                st = self.core.get_message_status(mid) if mid else "delivered"
                icon = "⏳" if st in ("queued", "sent") else "✓"
                self._append(f"me: {item['text']}  {icon}", "me")

    def _append(self, text, tag):
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n", tag)
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def _update_file_line(self, key, text, color="#888"):
        tag = f"file_{key}"
        ranges = self.chat.tag_ranges(tag)
        self.chat.configure(state="normal")
        if ranges:
            self.chat.delete(ranges[0], ranges[1])
            self.chat.insert(ranges[0], text, tag)
        else:
            self.chat.insert("end", text + "\n", tag)
            self.chat.see("end")
        self.chat.tag_configure(tag, foreground=color, font=("Menlo", 10))
        self.chat.configure(state="disabled")

    def on_send(self, _evt):
        if not self.current_peer_key:
            return
        text = self.input.get().strip()
        if not text:
            return
        self.input.delete(0, "end")
        self.core.submit(self.current_peer_key, text)

    def on_attach(self):
        if not self.current_peer_key:
            return
        path = filedialog.askopenfilename(title="Send file")
        if path:
            self.core.submit_file(self.current_peer_key, path)

    def on_add_contact(self):
        dlg = AddContactDialog(self.root)
        if dlg.result is None:
            return
        id_str, name = dlg.result
        try:
            self.core.add_peer(id_str, name)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_settings(self):
        def on_save(dmin, dmax, ping):
            self.core.set_settings(delay_min=dmin, delay_max=dmax,
                                   ping_interval=ping)
        SettingsDialog(self.root, self.core, on_save)

    def on_peer_menu(self, event):
        i = self.peer_list.nearest(event.y)
        if i < 0:
            return
        self.peer_list.selection_clear(0, "end")
        self.peer_list.selection_set(i)
        self.peer_list.activate(i)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _selected_peer_key(self):
        sel = self.peer_list.curselection()
        if not sel:
            return None
        peers = sorted(self.core.get_peers(),
                       key=lambda p: (p.name or p.peer_key).lower())
        if sel[0] >= len(peers):
            return None
        return peers[sel[0]].peer_key

    def on_rename_peer(self):
        pk = self._selected_peer_key()
        if not pk:
            return
        p = self._peer_by_key(pk)
        cur = p.name if p else ""
        new = simpledialog.askstring("Rename", "Display name:", initialvalue=cur,
                                     parent=self.root)
        if new is not None:
            self.core.rename_peer(pk, new.strip())
            self._refresh_peer_list()
            if pk == self.current_peer_key:
                self._render_chat()

    def on_remove_peer(self):
        pk = self._selected_peer_key()
        if not pk:
            return
        p = self._peer_by_key(pk)
        if not messagebox.askyesno("Remove contact",
                                   f"Remove {p.name if p else pk[:8]}?",
                                   parent=self.root):
            return
        self.core.remove_peer(pk)
        if pk == self.current_peer_key:
            self.current_peer_key = None
            self.input.config(state="disabled")
            self.attach_btn.config(state="disabled")
            self._render_chat()

    def _on_close(self):
        try:
            self.core.stop()
        except Exception:
            pass
        self.root.destroy()

    def poll_events(self):
        try:
            while True:
                self.handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(self.POLL_MS, self.poll_events)

    def handle(self, ev):
        kind = ev[0]
        if kind == "peer_added":
            self._refresh_peer_list()
        elif kind == "peer_removed":
            self._refresh_peer_list()
        elif kind == "peer_renamed":
            self._refresh_peer_list()
        elif kind == "settings_changed":
            self._append("— settings updated —", "sys")
        elif kind == "token_regenerated":
            new_id = ev[1]
            self._append(f"— identity regenerated —", "sys")
            self._append(f"new ID: {new_id}", "sys")
        elif kind == "session_up":
            pk = ev[1]
            self._peer_status[pk] = True
            self._refresh_peer_list()
            if pk == self.current_peer_key:
                self._render_chat()
        elif kind == "session_down":
            pk = ev[1]
            self._peer_status.pop(pk, None)
            self._refresh_peer_list()
            if pk == self.current_peer_key:
                self.status.config(text=f"○ offline  —  {self._peer_display(pk)}",
                                   fg="#888")
                self._append("— session lost —", "sys")
        elif kind == "denied":
            self._append("— peer denied the exchange token —", "sys")
        elif kind == "save_failed":
            self._append(f"⚠ {ev[1]}", "sys")
        elif kind == "peer_msg":
            pk, text = ev[1], ev[2]
            if pk == self.current_peer_key:
                self._append(f"peer: {text}", "peer")
        elif kind == "msg_queued":
            pk, mid, body = ev[1], ev[2], ev[3]
            if pk == self.current_peer_key:
                tag = f"icon_{mid}"
                self.chat.tag_configure(tag, foreground="#666", font=("Menlo", 9))
                self.chat.configure(state="normal")
                self.chat.insert("end", f"me: {body}  ", "me")
                self.chat.insert("end", "⏳", tag)
                self.chat.insert("end", "\n")
                self.chat.see("end")
                self.chat.configure(state="disabled")
        elif kind == "msg_delivered":
            pk, mid = ev[1], ev[2]
            if pk == self.current_peer_key:
                tag = f"icon_{mid}"
                ranges = self.chat.tag_ranges(tag)
                if ranges:
                    self.chat.tag_configure(tag, foreground="#4caf50")
                    self.chat.configure(state="normal")
                    self.chat.delete(ranges[0], ranges[1])
                    self.chat.insert(ranges[0], "✓", tag)
                    self.chat.configure(state="disabled")
        elif kind == "pong":
            pk, rtt = ev[1], ev[2]
            if pk == self.current_peer_key:
                color = ("#4caf50" if rtt < 200
                         else "#ffb300" if rtt < 1000 else "#f44336")
                self.status.config(
                    text=f"● online  —  {self._peer_display(pk)}  ·  ping {rtt:.0f}ms",
                    fg=color)
        elif kind == "ping_unavailable":
            self._append("— ping unavailable (no session) —", "sys")
        elif kind == "file_queued":
            pk, fid, name, size = ev[1], ev[2], ev[3], ev[4]
            if pk == self.current_peer_key:
                self._file_names[f"out_{fid}"] = name
                self._update_file_line(f"out_{fid}",
                                       f"me: [FILE] {name} ({fmt_size(size)})  ⏳",
                                       "#7fb3ff")
        elif kind == "file_offer":
            pk, fid, name, size = ev[1], ev[2], ev[3], ev[4]
            if pk == self.current_peer_key:
                pname = self._peer_display(pk)
                FileOfferDialog(
                    self.root, pname, name, size,
                    on_accept=lambda f=fid: self.core.accept_file(f),
                    on_decline=lambda f=fid: self.core.decline_file(f))
                self._file_names[f"in_{fid}"] = name
                self._update_file_line(f"in_{fid}",
                                       f"peer: [FILE] {name} ({fmt_size(size)})  — waiting",
                                       "#a0e0a0")
        elif kind == "file_progress":
            pk, fid, direction, cur, total = ev[1], ev[2], ev[3], ev[4], ev[5]
            if pk == self.current_peer_key:
                pct = int(cur * 100 / total) if total else 0
                prefix = "me" if direction == "out" else "peer"
                fname = self._file_names.get(f"{direction}_{fid}", fid[:8])
                arrow = "↑" if direction == "out" else "↓"
                color = "#7fb3ff" if direction == "out" else "#a0e0a0"
                self._update_file_line(
                    f"{direction}_{fid}",
                    f"{prefix}: [FILE] {fname}  {arrow} {pct}% "
                    f"({fmt_size(cur)} / {fmt_size(total)})", color)
        elif kind == "file_done":
            pk, fid, direction = ev[1], ev[2], ev[3]
            path = ev[4] if len(ev) > 4 else None
            if pk == self.current_peer_key:
                fname = self._file_names.get(f"{direction}_{fid}", fid[:8])
                prefix = "me" if direction == "out" else "peer"
                if direction == "out":
                    self._update_file_line(f"out_{fid}",
                                           f"me: [FILE] {fname}  ✓ (sha256 ok)", "#4caf50")
                else:
                    self._update_file_line(f"in_{fid}",
                                           f"peer: [FILE] {fname}  ✓ saved → {path}",
                                           "#4caf50")
        elif kind == "file_declined":
            pk, fid = ev[1], ev[2]
            if pk == self.current_peer_key:
                fname = self._file_names.get(f"out_{fid}", fid[:8])
                self._update_file_line(f"out_{fid}",
                                       f"me: [FILE] {fname}  ✗ declined", "#f44336")
        elif kind == "file_failed":
            pk, fid, reason = ev[1], ev[2], ev[3]
            if pk == self.current_peer_key:
                if fid:
                    fname = (self._file_names.get(f"out_{fid}")
                             or self._file_names.get(f"in_{fid}") or fid[:8])
                    self._update_file_line(f"out_{fid}",
                                           f"[FILE] {fname}  ✗ {reason}", "#f44336")
                else:
                    self._append(f"[FILE] ✗ {reason}", "sys")


def run_gui():
    root = tk.Tk()
    root.title("Paragon Chat")
    root.configure(bg="#1e1e1e")
    root.geometry("560x420")

    delay_min = float(os.environ.get("PARAGON_DELAY_MIN", "0"))
    delay_max = float(os.environ.get("PARAGON_DELAY_MAX", "0"))
    ping_interval = float(os.environ.get("PARAGON_PING_INTERVAL", "30"))
    socks_host = os.environ.get("PARAGON_SOCKS_HOST", "127.0.0.1")
    socks_port = int(os.environ.get("PARAGON_SOCKS_PORT", "9050"))
    listen_host = os.environ.get("PARAGON_LISTEN_HOST") or None
    _lp = os.environ.get("PARAGON_LISTEN_PORT")
    listen_port = int(_lp) if _lp else None
    net_kwargs = dict(socks_host=socks_host, socks_port=socks_port,
                      listen_host=listen_host, listen_port=listen_port)

    closed = {"flag": False}

    def on_close_setup():
        closed["flag"] = True
        try:
            root.destroy()
        except Exception:
            pass

    root.protocol("WM_DELETE_WINDOW", on_close_setup)

    done = tk.BooleanVar(root, False)
    res = {"v": None}

    def on_done(path, pw, is_new):
        res["v"] = (path, pw, is_new)
        done.set(True)

    def on_cancel():
        res["v"] = None
        done.set(True)

    _build_account_view(root, on_done, on_cancel)
    root.wait_variable(done)
    if closed["flag"] or res["v"] is None:
        if not closed["flag"]:
            root.destroy()
        return
    path, password, is_new = res["v"]
    _clear(root)

    if is_new:
        root.geometry("640x640")
        idone = tk.BooleanVar(root, False)
        ires = {"v": None}

        def on_id_done(payload):
            ires["v"] = payload
            idone.set(True)

        def on_id_cancel():
            ires["v"] = None
            idone.set(True)

        _build_identity_view(root, on_id_done, on_id_cancel)
        root.wait_variable(idone)
        if closed["flag"] or ires["v"] is None:
            if not closed["flag"]:
                root.destroy()
            return
        payload = ires["v"]
        _clear(root)
        try:
            core = Core(path, password, my_identity=payload["identity"],
                        onion_seed=payload.get("onion_seed"),
                        hs_dir=payload.get("hs_dir"),
                        onion_only=bool(payload.get("onion_seed")),
                        delay_min=delay_min, delay_max=delay_max,
                        ping_interval=ping_interval, **net_kwargs)
        except Exception as e:
            messagebox.showerror("Paragon Chat", f"Create failed:\n{e}")
            root.destroy()
            return
    else:
        try:
            core = Core(path, password, delay_min=delay_min,
                        delay_max=delay_max, ping_interval=ping_interval,
                        **net_kwargs)
        except Exception as e:
            messagebox.showerror("Paragon Chat", f"Open failed:\n{e}")
            root.destroy()
            return

    core.start()
    ChatUI(root, core)
    try:
        root.mainloop()
    finally:
        if core._loop is not None:
            try:
                core.stop()
            except Exception:
                pass


def _clear(root):
    for w in list(root.winfo_children()):
        w.destroy()
    for name in root.protocol():
        try:
            root.protocol(name, "")
        except Exception:
            pass
    try:
        root.unbind("<Return>")
    except Exception:
        pass


def _build_account_view(root, on_done, on_cancel):
    P = dict(padx=16)
    tk.Label(root, text="ACCOUNT (.paragon file)", bg="#1e1e1e", fg="#7fb3ff",
             font=("Menlo", 12, "bold")).pack(anchor="w", **P, pady=(16, 8))
    tk.Label(root, text="Path:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(anchor="w", **P)
    row = tk.Frame(root, bg="#1e1e1e")
    row.pack(fill="x", **P)
    path_entry = tk.Entry(row, bg="#333", fg="white", font=("Menlo", 10),
                          insertbackground="white", relief="flat")
    path_entry.insert(0, os.path.abspath("default.paragon"))
    path_entry.pack(side="left", fill="x", expand=True, ipady=4)
    hint = tk.Label(root, text="", bg="#1e1e1e", fg="#a0e0a0",
                    font=("Menlo", 9, "italic"), wraplength=500, justify="left")
    hint.pack(anchor="w", **P, pady=(2, 8))
    tk.Label(root, text="Password:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(anchor="w", **P, pady=(8, 0))
    pw1 = tk.Entry(root, show="*", bg="#333", fg="white", font=("Menlo", 10),
                   insertbackground="white", relief="flat")
    pw1.pack(fill="x", **P, ipady=4)
    confirm_label = tk.Label(root, text="Confirm:", bg="#1e1e1e", fg="#aaa",
                             font=("Menlo", 9))
    confirm_label.pack(anchor="w", **P, pady=(8, 0))
    pw2 = tk.Entry(root, show="*", bg="#333", fg="white", font=("Menlo", 10),
                   insertbackground="white", relief="flat")
    pw2.pack(fill="x", **P, ipady=4)
    err = tk.Label(root, text="", bg="#1e1e1e", fg="#f44336",
                   font=("Menlo", 9), wraplength=500, justify="left")
    err.pack(anchor="w", **P, pady=(4, 4))

    def update_hint(*_):
        p = path_entry.get().strip()
        if not p:
            hint.config(text="", fg="#666")
            return
        if os.path.exists(p):
            hint.config(text="File exists — will OPEN (password only)", fg="#a0e0a0")
            confirm_label.pack_forget()
            pw2.pack_forget()
        else:
            hint.config(text="File will be CREATED — password required twice",
                        fg="#ffb300")
            confirm_label.pack(anchor="w", padx=16, pady=(8, 0))
            pw2.pack(fill="x", padx=16, ipady=4)

    path_entry.bind("<KeyRelease>", update_hint)
    update_hint()

    def browse():
        existing = os.path.exists(path_entry.get().strip())
        if existing:
            p = filedialog.askopenfilename(parent=root, title="Open .paragon",
                                           filetypes=[("Paragon account", "*.paragon"), ("All", "*.*")])
        else:
            p = filedialog.asksaveasfilename(parent=root, title="Save .paragon",
                                             defaultextension=".paragon",
                                             filetypes=[("Paragon account", "*.paragon"), ("All", "*.*")])
        if p:
            path_entry.delete(0, "end")
            path_entry.insert(0, p)
            update_hint()

    tk.Button(row, text="…", command=browse, bg="#444", fg="white",
              font=("Menlo", 10), relief="flat", width=3).pack(side="left", padx=(4, 0), ipady=4)

    def submit(_=None):
        p = path_entry.get().strip()
        if not p:
            err.config(text="Path required")
            return
        if not pw1.get():
            err.config(text="Password required")
            return
        exists = os.path.exists(p)
        if exists:
            on_done(p, pw1.get(), False)
        else:
            if pw2.get() != pw1.get():
                err.config(text="Passwords do not match")
                return
            on_done(p, pw1.get(), True)

    root.bind("<Return>", submit)
    btns = tk.Frame(root, bg="#1e1e1e")
    btns.pack(fill="x", **P, pady=(0, 16))
    tk.Button(btns, text="CANCEL", command=on_cancel, bg="#555", fg="white",
              font=("Menlo", 10), relief="flat", activebackground="#666").pack(
                  side="left", ipady=4, ipadx=8)
    tk.Button(btns, text="CONTINUE", command=submit, bg="#4caf50", fg="white",
              font=("Menlo", 11, "bold"), relief="flat", activebackground="#66bb6a").pack(
                  side="right", ipady=4, ipadx=16)


def _build_identity_view(root, on_done, on_cancel):
    P = dict(padx=14)
    state = {"onion_seed": None}
    tk.Label(root, text="MY IDENTITY", bg="#1e1e1e", fg="#7fb3ff",
             font=("Menlo", 11, "bold")).pack(anchor="w", **P, pady=(14, 4))
    tk.Label(root,
             text="Generate a Tor v3 onion identity (recommended: hides your IP). "
                  "Share the resulting ID with peers.",
             bg="#1e1e1e", fg="#666", font=("Menlo", 9, "italic"),
             wraplength=600, justify="left").pack(anchor="w", **P)
    onion_row = tk.Frame(root, bg="#1e1e1e")
    onion_row.pack(fill="x", **P, pady=(8, 4))
    tk.Button(onion_row, text="Generate onion identity (v3)",
              command=lambda: gen_onion(), bg="#4caf50", fg="white",
              font=("Menlo", 10, "bold"), relief="flat",
              activebackground="#66bb6a").pack(side="left", ipady=4, ipadx=8)
    tk.Button(onion_row, text="Generate plain (IP/host)",
              command=lambda: gen_plain(), bg="#444", fg="white",
              font=("Menlo", 9), relief="flat",
              activebackground="#555").pack(side="left", padx=(6, 0), ipady=4)
    hs_row = tk.Frame(root, bg="#1e1e1e")
    hs_row.pack(fill="x", **P, pady=(0, 4))
    tk.Label(hs_row, text="Tor HS dir:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(side="left")
    hs_dir_entry = tk.Entry(hs_row, bg="#333", fg="white", font=("Menlo", 9),
                            insertbackground="white", relief="flat")
    hs_dir_entry.insert(0, "hs_9001")
    hs_dir_entry.pack(side="left", fill="x", expand=True, padx=(4, 4), ipady=3)

    def browse_hs():
        p = filedialog.askdirectory(parent=root, title="Tor HiddenService dir")
        if p:
            hs_dir_entry.delete(0, "end"); hs_dir_entry.insert(0, p)
    tk.Button(hs_row, text="...", command=browse_hs, bg="#444", fg="white",
              font=("Menlo", 10), relief="flat", width=3).pack(side="left", ipady=3)
    tk.Label(root, text="ID (base64):", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(anchor="w", **P, pady=(4, 0))
    my_id = tk.Entry(root, bg="#333", fg="white", font=("Menlo", 10),
                     insertbackground="white", relief="flat")
    my_id.pack(fill="x", **P, pady=(0, 4), ipady=4)
    row = tk.Frame(root, bg="#1e1e1e")
    row.pack(fill="x", **P, pady=(0, 6))
    tk.Label(row, text="Host:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(side="left")
    my_host = tk.Entry(row, bg="#333", fg="white", font=("Menlo", 10),
                       insertbackground="white", relief="flat", width=20)
    my_host.insert(0, "127.0.0.1")
    my_host.pack(side="left", padx=(4, 10), ipady=3)
    tk.Label(row, text="Port:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(side="left")
    my_port = tk.Entry(row, bg="#333", fg="white", font=("Menlo", 10),
                       insertbackground="white", relief="flat", width=7)
    my_port.insert(0, "9001")
    my_port.pack(side="left", padx=(4, 10), ipady=3)
    tk.Label(row, text="Token:", bg="#1e1e1e", fg="#aaa",
             font=("Menlo", 9)).pack(side="left")
    my_token = tk.Entry(row, bg="#333", fg="white", font=("Menlo", 10),
                        insertbackground="white", relief="flat")
    my_token.pack(side="left", fill="x", expand=True, padx=(4, 0), ipady=3)
    err = tk.Label(root, text="", bg="#1e1e1e", fg="#f44336",
                   font=("Menlo", 9), wraplength=600, justify="left")
    err.pack(anchor="w", **P, pady=(4, 4))

    def gen_onion():
        err.config(text="")
        try:
            port = int(my_port.get())
        except ValueError:
            err.config(text="Port must be a number")
            return
        onion_id = generate_onion_identity()
        state["onion_seed"] = onion_id["seed"]
        onion = onion_id["onion"]
        token = onion_id["token"]
        my_host.delete(0, "end"); my_host.insert(0, onion)
        my_token.delete(0, "end"); my_token.insert(0, token)
        my_id.delete(0, "end"); my_id.insert(0, encode_id(onion, port, token))
        hs_dir = hs_dir_entry.get().strip() or f"hs_{port}"
        hs_dir_entry.delete(0, "end"); hs_dir_entry.insert(0, hs_dir)
        try:
            write_hidden_service_dir(hs_dir, onion_id, force=False)
            err.config(text=f"Onion generated. HS dir ready at {hs_dir}",
                       fg="#a0e0a0")
        except Exception as e:
            err.config(text=f"Onion generated, HS write failed: {e}", fg="#ffb300")

    def gen_plain():
        err.config(text="")
        state["onion_seed"] = None
        try:
            port = int(my_port.get())
        except ValueError:
            err.config(text="Port must be a number")
            return
        host = my_host.get().strip() or "127.0.0.1"
        id_str, token = generate_identity(host, port)
        my_id.delete(0, "end"); my_id.insert(0, id_str)
        my_token.delete(0, "end"); my_token.insert(0, token)
        err.config(text="Plain identity generated (IP will be visible)", fg="#ffb300")

    def copy_id():
        v = my_id.get().strip()
        if not v:
            err.config(text="No ID to copy", fg="#ffb300")
            return
        root.clipboard_clear(); root.clipboard_append(v)
        err.config(text="ID copied", fg="#a0e0a0")
    tk.Button(root, text="Copy my ID", command=copy_id,
              bg="#444", fg="white", font=("Menlo", 9), relief="flat",
              activebackground="#555").pack(anchor="w", **P, pady=(0, 6), ipady=3)

    def submit():
        err.config(text="")
        h = my_host.get().strip()
        ps = my_port.get().strip()
        t = my_token.get().strip()
        if not (h and ps and t):
            err.config(text="Generate an identity first (or fill host/port/token)")
            return
        try:
            port = int(ps)
        except ValueError:
            err.config(text="Port must be a number")
            return
        identity = (h, port, t)
        seed = state["onion_seed"]
        hs_dir = hs_dir_entry.get().strip() if seed is not None else None
        if seed is not None and not hs_dir:
            err.config(text="Tor HS dir is required for onion identity")
            return
        on_done({"identity": identity, "onion_seed": seed, "hs_dir": hs_dir})

    btns = tk.Frame(root, bg="#1e1e1e")
    btns.pack(fill="x", **P, pady=(0, 14))
    tk.Button(btns, text="CANCEL", command=on_cancel, bg="#555", fg="white",
              font=("Menlo", 10), relief="flat", activebackground="#666").pack(
                  side="left", ipady=4, ipadx=8)
    tk.Button(btns, text="CREATE ACCOUNT", command=submit, bg="#4caf50",
              fg="white", font=("Menlo", 11, "bold"), relief="flat",
              activebackground="#66bb6a").pack(side="right", ipady=4, ipadx=16)


def run_cli():
    if len(sys.argv) < 2:
        print("usage:")
        print("  python chat.py --gen [host] [port]")
        print("  python chat.py <account.paragon>")
        print("  python chat.py <account.paragon> <my_id>")
        print("  python chat.py            (GUI)")
        return
    if sys.argv[1] == "--gen":
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 9001
        id_str, token = generate_identity(host, port)
        print(f"ID: {id_str}")
        print(f"TOKEN: {token}")
        return
    path = sys.argv[1]
    password = getpass.getpass("Account password: ")
    if not os.path.exists(path):
        if len(sys.argv) != 3:
            print("new account: python chat.py <path> <my_id>")
            return
        mine = decode_id(sys.argv[2])
        core = Core(path, password, my_identity=mine)
    else:
        core = Core(path, password)
    core.start()
    print(f"my ID: {core.my_id_str}")
    print("type 'to <peer_key> <text>' or 'exit'")
    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            if line.strip() == "exit":
                break
            if line.startswith("to "):
                parts = line[3:].split(" ", 1)
                if len(parts) == 2:
                    pk, text = parts
                    if pk in core.peers:
                        core.submit(pk, text)
                    else:
                        print(f"no peer {pk}; peers: {list(core.peers)}")
    except KeyboardInterrupt:
        pass
    finally:
        core.stop()


def main():
    if len(sys.argv) == 1:
        run_gui()
    else:
        run_cli()


if __name__ == "__main__":
    main()