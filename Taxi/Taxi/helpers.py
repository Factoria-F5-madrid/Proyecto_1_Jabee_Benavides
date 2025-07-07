import json
import os
import re
import hashlib
import logging
from tkinter import messagebox

# -------------------------------
# Funciones utilitarias
# -------------------------------

def calcular_tarifa(tarifa_detencion, tarifa_movimiento, tiempo_detenido, tiempo_movimiento):
    return round(tarifa_detencion * tiempo_detenido + tarifa_movimiento * tiempo_movimiento, 2)

def validar_password(password):
    """
    Verifica si una contraseña cumple con los requisitos de seguridad:
    - Mínimo 8 caracteres
    - Al menos una mayúscula
    - Al menos una minúscula
    - Al menos un número
    - Al menos un símbolo especial
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def cargar_json_seguro(archivo, default):
    try:
        if os.path.exists(archivo):
            with open(archivo, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"Error cargando {archivo}: {str(e)}")
    return default

def guardar_json_seguro(archivo, data):
    try:
        with open(archivo, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error guardando {archivo}: {str(e)}")
        return False


# -------------------------------
# Clase principal de la app
# -------------------------------

class MiAplicacion:
    def cambiar_password_admin(self):
        nueva_password = self.nueva_password_entry.get()
        confirmacion = self.confirmar_password_entry.get()

        if nueva_password != confirmacion:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        if not validar_password(nueva_password):
            messagebox.showerror("Error", "La contraseña no cumple con los requisitos de seguridad")
            return

        exito, mensaje = self.autenticador.modificar_usuario(
            'admin',
            nueva_password=nueva_password
        )

        if exito:
            self.configurador.marcar_primer_inicio_completado()
            messagebox.showinfo("Éxito", "Contraseña cambiada con éxito")
            self.nueva_password_entry.master.destroy()
        else:
            messagebox.showerror("Error", mensaje)

    def crear_nuevo_usuario(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if password != confirm_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        if not validar_password(password):
            messagebox.showerror("Error", "La contraseña no cumple con los requisitos de seguridad")
            return

        exito, mensaje = self.autenticador.crear_usuario(username, password)
        if exito:
            messagebox.showinfo("Éxito", "Usuario creado correctamente")
            self.limpiar_campos_usuario()
        else:
            messagebox.showerror("Error", mensaje)

    def guardar_cambios_usuario(self):
        username = self.username_entry.get()
        nueva_password = self.nueva_password_entry.get()
        confirmar_password = self.confirmar_password_entry.get()

        if nueva_password and nueva_password != confirmar_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        if nueva_password and not validar_password(nueva_password):
            messagebox.showerror("Error", "La nueva contraseña no cumple con los requisitos de seguridad")
            return

        exito, mensaje = self.autenticador.modificar_usuario(
            username,
            nueva_password=nueva_password if nueva_password else None
        )

        if exito:
            messagebox.showinfo("Éxito", "Cambios guardados correctamente")
        else:
            messagebox.showerror("Error", mensaje)

    def cambiar_password_personal(self):
        usuario = self.usuario_actual
        nueva_password = self.nueva_password_entry.get()
        confirmar_password = self.confirmar_password_entry.get()

        if nueva_password != confirmar_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        if not validar_password(nueva_password):
            messagebox.showerror("Error", "La nueva contraseña no cumple con los requisitos de seguridad")
            return

        exito, mensaje = self.autenticador.modificar_usuario(
            usuario,
            nueva_password=nueva_password
        )

        if exito:
            messagebox.showinfo("Éxito", "Contraseña cambiada con éxito")
            self.nueva_password_entry.master.destroy()
        else:
            messagebox.showerror("Error", mensaje)

