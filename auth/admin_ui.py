# auth/admin_ui.py
import secrets
import streamlit as st

from auth.auth import (
    audit,
    load_users,
    create_user,
    set_enabled,
    set_role,
    set_password,
    verify_password,
)
from auth.ui import has_role

def _admin_guard() -> bool:
    if not has_role("admin"):
        st.error("Acceso restringido.")
        return False
    return True

def _require_admin_password(pw: str) -> bool:
    admin_user = (st.session_state.auth or {}).get("username", "")
    if not admin_user:
        st.error("Sesión inválida.")
        return False
    if not pw:
        st.error("Introduce tu contraseña de admin.")
        return False
    if not verify_password(admin_user, pw):
        audit("admin_reauth_failed", admin_user, {})
        st.error("Contraseña de admin incorrecta.")
        return False
    return True

def _persist_temp_pwd(key: str, value: str):
    st.session_state[key] = value

def _show_temp_pwd(key: str, title: str):
    v = st.session_state.get(key)
    if v:
        st.success(title)
        st.code(v)
        st.caption("Copiala ahora. No se vuelve a mostrar tras refrescar si la borras manualmente.")
        if st.button("Borrar password temporal mostrada", use_container_width=True, key=key + "_clear"):
            st.session_state.pop(key, None)
            st.rerun()

def render_admin_panel():
    if not _admin_guard():
        return

    st.subheader("Administration")
    st.caption("Gestión de usuarios. Operaciones sensibles requieren contraseña de admin. Todo queda auditado.")

    users = load_users() or {}

    # Tabla resumen (sin hashes)
    rows = []
    for u, v in sorted(users.items()):
        rows.append({
            "Usuario": u,
            "Rol": v.get("role", "viewer"),
            "Activo": v.get("enabled", True),
            "Must change": v.get("must_change", False),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

    audit("admin_view_users", (st.session_state.auth or {}).get("username",""), {"count": len(rows)})

    st.divider()
    t_create, t_manage = st.tabs(["Create user", "Manage users"])

    # ---------------- CREATE ----------------
    with t_create:
        st.markdown("### Create user")
        _show_temp_pwd("temp_pwd_last_created", "Usuario creado. Password temporal:")

        with st.form("create_user_form", clear_on_submit=False):
            new_u = st.text_input("Username", placeholder="e.g. analyst1")
            new_role = st.selectbox("Role", ["viewer", "analyst", "ciso", "admin"], index=1)
            new_enabled = st.checkbox("Enabled", value=True)
            admin_pw = st.text_input("Admin password (required)", type="password")

            submitted = st.form_submit_button("Create", use_container_width=True)

        if submitted:
            if not _require_admin_password(admin_pw):
                st.stop()
            try:
                temp_pwd, _ = create_user(new_u, new_role, enabled=new_enabled)
                audit(
                    "admin_create_user",
                    (st.session_state.auth or {}).get("username",""),
                    {"created": new_u, "role": new_role, "enabled": new_enabled},
                )
                _persist_temp_pwd("temp_pwd_last_created", temp_pwd)
                st.rerun()
            except Exception as e:
                st.error(str(e))

    # ---------------- MANAGE ----------------
    with t_manage:
        st.markdown("### Manage users")
        _show_temp_pwd("temp_pwd_last_reset", "Password temporal (reset) generado:")

        if not users:
            st.info("No hay usuarios.")
            return

        sel = st.selectbox("Select user", list(sorted(users.keys())), key="sel_user_manage")
        cur = users.get(sel, {}) or {}

        with st.form("manage_user_form", clear_on_submit=False):
            role = st.selectbox(
                "Role",
                ["viewer", "analyst", "ciso", "admin"],
                index=["viewer","analyst","ciso","admin"].index(cur.get("role","viewer")),
            )
            enabled = st.checkbox("Enabled", value=bool(cur.get("enabled", True)))
            st.caption("Acciones sensibles requieren contraseña de admin.")
            admin_pw2 = st.text_input("Admin password (required)", type="password", key="admin_pw_manage")

            c1, c2, c3 = st.columns(3)
            with c1:
                btn_save = st.form_submit_button("Save changes", use_container_width=True)
            with c2:
                btn_reset = st.form_submit_button("Reset password (temp)", use_container_width=True)
            with c3:
                btn_force = st.form_submit_button("Force must_change", use_container_width=True)

        if btn_save or btn_reset or btn_force:
            if not _require_admin_password(admin_pw2):
                st.stop()

        if btn_save:
            try:
                set_role(sel, role)
                set_enabled(sel, enabled)
                audit("admin_update_user", (st.session_state.auth or {}).get("username",""), {"target": sel, "role": role, "enabled": enabled})
                st.success("Cambios aplicados.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        if btn_reset:
            try:
                temp_pwd = secrets.token_urlsafe(14)
                set_password(sel, temp_pwd, must_change=True)
                audit("admin_reset_password", (st.session_state.auth or {}).get("username",""), {"target": sel})
                _persist_temp_pwd("temp_pwd_last_reset", temp_pwd)
                st.rerun()
            except Exception as e:
                st.error(str(e))

        if btn_force:
            try:
                temp_pwd = secrets.token_urlsafe(14)
                set_password(sel, temp_pwd, must_change=True)
                audit("admin_force_must_change", (st.session_state.auth or {}).get("username",""), {"target": sel})
                _persist_temp_pwd("temp_pwd_last_reset", temp_pwd)
                st.rerun()
            except Exception as e:
                st.error(str(e))
