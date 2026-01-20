# auth/ui.py
import time
import streamlit as st
from auth.auth import (
    authenticate,
    audit,
    session_is_valid,
    get_user,
    set_password,
    verify_password,
)

def init_auth_state():
    if "auth" not in st.session_state:
        st.session_state.auth = None
    if "auth_lock" not in st.session_state:
        st.session_state.auth_lock = {"fails": 0, "until": 0}
    if "consent" not in st.session_state:
        st.session_state.consent = False

def logout():
    if st.session_state.get("auth"):
        audit("logout", st.session_state.auth.get("username", ""))
    st.session_state.auth = None
    st.session_state.consent = False

def _force_password_change(username: str) -> bool:
    st.markdown("## Cambio de contraseña requerido")
    st.caption("Por seguridad, debes establecer una nueva contraseña antes de continuar.")

    current = st.text_input("Contraseña actual", type="password", key="chg_cur")
    new1 = st.text_input("Nueva contraseña", type="password", key="chg_new1")
    new2 = st.text_input("Repite la nueva contraseña", type="password", key="chg_new2")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Actualizar contraseña", use_container_width=True):
            if not current or not new1 or not new2:
                st.error("Completa todos los campos.")
                return False
            if new1 != new2:
                st.error("Las nuevas contraseñas no coinciden.")
                return False
            if len(new1) < 12:
                st.error("La contraseña debe tener al menos 12 caracteres.")
                return False
            if not verify_password(username, current):
                audit("password_change_failed", username, {"reason": "bad_current"})
                st.error("Contraseña actual incorrecta.")
                return False

            set_password(username, new1, must_change=False)
            audit("password_changed", username, {})
            st.success("Contraseña actualizada. Continúa.")
            st.rerun()

    with col2:
        st.button("Cerrar sesión", on_click=logout, use_container_width=True)

    return False

def require_login():
    init_auth_state()

    if st.session_state.auth and not session_is_valid(st.session_state.auth):
        audit("session_expired", st.session_state.auth.get("username", ""))
        logout()

    if st.session_state.auth:
        # Enforce must_change
        u = get_user(st.session_state.auth.get("username", ""))
        if u and u.get("must_change") is True:
            return _force_password_change(st.session_state.auth.get("username", ""))
        return True

    st.markdown("## Iniciar sesión")
    st.caption("Uso solo autorizado. Todas las acciones quedan registradas.")

    now = time.time()
    lock = st.session_state.auth_lock
    if lock["until"] > now:
        wait_s = int(lock["until"] - now)
        st.error(f"Demasiados intentos. Inténtalo de nuevo en {wait_s}s.")
        return False

    username = st.text_input("Usuario", key="login_user")
    password = st.text_input("Contraseña", type="password", key="login_pass")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Entrar", use_container_width=True):
            user = authenticate(username.strip(), password)
            if not user:
                lock["fails"] += 1
                if lock["fails"] >= 5:
                    lock["until"] = time.time() + 60
                audit("login_failed", username.strip(), {"fails": lock["fails"]})
                st.error("Credenciales inválidas.")
                return False

            st.session_state.auth = {
                "username": user["username"],
                "role": user["role"],
                "login_ts": int(time.time()),
            }
            st.session_state.auth_lock = {"fails": 0, "until": 0}
            audit("login_ok", user["username"], {"role": user["role"]})
            st.success("Sesión iniciada.")
            st.rerun()

    with col2:
        st.button("Salir", on_click=logout, use_container_width=True)

    return False

def require_consent():
    st.markdown("### Consentimiento")
    st.write("Confirma que tienes autorización explícita para evaluar estos activos.")
    st.session_state.consent = st.checkbox(
        "Tengo autorización y acepto que la actividad quede registrada.",
        value=st.session_state.consent
    )
    if not st.session_state.consent:
        st.warning("No puedes ejecutar acciones de Recon sin consentimiento.")
        return False
    return True

def has_role(*allowed_roles: str) -> bool:
    role = (st.session_state.auth or {}).get("role", "viewer")
    return role in allowed_roles

def render_session_sidebar():
    with st.sidebar:
        st.markdown("### Sesión")
        u = st.session_state.auth
        st.write(f"Usuario: **{u['username']}**")
        st.write(f"Rol: **{u['role']}**")
        st.button("Cerrar sesión", on_click=logout, use_container_width=True)
