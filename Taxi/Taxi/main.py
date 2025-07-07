import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from functools import partial
from datetime import datetime
import logging
import os
import json
from configurador import Configurador
from autenticador import Autenticador
from taximetro import Taximetro

class TaximetroGUI:
    def __init__(self, root, taximetro, autenticador, configurador):
        self.root = root
        self.taximetro = taximetro
        self.autenticador = autenticador
        self.configurador = configurador
        self.usuario_actual = None
        self.viaje_activo = False
        
        self.root.title("Sistema de Taxímetro Avanzado")
        self.root.geometry("700x550")
        self.root.resizable(True, True)
        
        self.crear_interfaz_login()
        
        if self.configurador.config.get('primer_inicio', True):
            self.mostrar_cambio_password_obligatorio()
    
    def mostrar_cambio_password_obligatorio(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("Cambio de Contraseña Obligatorio")
        ventana.geometry("500x300")
        ventana.grab_set()
        ventana.transient(self.root)
        
        tk.Label(ventana, text="PRIMER INICIO - CAMBIO DE CONTRASEÑA", 
                font=("Arial", 14, "bold"), fg="red").pack(pady=10)
        
        tk.Label(ventana, text="Por razones de seguridad, debe cambiar la contraseña del usuario admin.", 
                wraplength=400).pack(pady=5)
        
        tk.Label(ventana, text="Requisitos de contraseña:", font=("Arial", 10, "bold")).pack(pady=5)
        tk.Label(ventana, text="- Mínimo 8 caracteres\n- Al menos una mayúscula y una minúscula\n- Al menos un número\n- Al menos un carácter especial (!@#$%^&*)", 
                justify="left").pack()
        
        tk.Label(ventana, text="Nueva Contraseña:").pack(pady=5)
        self.nueva_password_entry = tk.Entry(ventana, show="*")
        self.nueva_password_entry.pack(pady=5)
        
        tk.Label(ventana, text="Confirmar Contraseña:").pack(pady=5)
        self.confirmar_password_entry = tk.Entry(ventana, show="*")
        self.confirmar_password_entry.pack(pady=5)
        
        tk.Button(ventana, text="Cambiar Contraseña", 
                 command=self.cambiar_password_admin).pack(pady=15)
        
        ventana.protocol("WM_DELETE_WINDOW", lambda: None)
    
    def cambiar_password_admin(self):
        nueva_password = self.nueva_password_entry.get()
        confirmacion = self.confirmar_password_entry.get()
        
        if nueva_password != confirmacion:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if not self.autenticador.validar_password(nueva_password):
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
    
    def crear_interfaz_login(self):
        self.limpiar_interfaz()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)
        
        tk.Label(frame, text="Sistema de Taxímetro", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        tk.Label(frame, text="Usuario:").grid(row=1, column=0, sticky="e", pady=5)
        self.usuario_entry = tk.Entry(frame, width=25)
        self.usuario_entry.grid(row=1, column=1, pady=5)
        self.usuario_entry.focus()
        
        tk.Label(frame, text="Contraseña:").grid(row=2, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(frame, show="*", width=25)
        self.password_entry.grid(row=2, column=1, pady=5)
        
        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        tk.Button(btn_frame, text="Iniciar Sesión", width=15, 
                 command=self.verificar_credenciales).pack(side="left", padx=10)
        
        tk.Button(btn_frame, text="Salir", width=15, 
                 command=self.root.quit).pack(side="left", padx=10)
        
        info_frame = tk.LabelFrame(frame, text="Información de Acceso", padx=10, pady=10)
        info_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="we")
        
        tk.Label(info_frame, text="Usuario por defecto: admin\nContraseña por defecto: 1234", 
                justify="left").pack()
        tk.Label(info_frame, text="Después del primer inicio, cambie la contraseña", 
                fg="red", font=("Arial", 9)).pack(pady=5)
    
    def verificar_credenciales(self):
        usuario = self.usuario_entry.get()
        password = self.password_entry.get()
        
        if self.autenticador.autenticar(usuario, password):
            self.usuario_actual = usuario
            self.crear_interfaz_principal()
        else:
            messagebox.showerror("Error", "Credenciales incorrectas")
    
    def crear_interfaz_principal(self):
        self.limpiar_interfaz()
        
        tab_control = ttk.Notebook(self.root)
        
        tab_taximetro = ttk.Frame(tab_control)
        tab_control.add(tab_taximetro, text='Taxímetro')
        
        if self.autenticador.es_admin(self.usuario_actual):
            tab_admin = ttk.Frame(tab_control)
            tab_control.add(tab_admin, text='Administración')
            
            tab_usuarios = ttk.Frame(tab_control)
            tab_control.add(tab_usuarios, text='Usuarios')
        
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)
        
        self.construir_taximetro_tab(tab_taximetro)
        
        if self.autenticador.es_admin(self.usuario_actual):
            self.construir_admin_tab(tab_admin)
            self.construir_usuarios_tab(tab_usuarios)
        
        self.status_var = tk.StringVar()
        self.status_var.set(f"Usuario: {self.usuario_actual} | {'(Admin)' if self.autenticador.es_admin(self.usuario_actual) else ''}")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        btn_cerrar_sesion = tk.Button(self.root, text="Cerrar Sesión", command=self.cerrar_sesion)
        btn_cerrar_sesion.pack(side=tk.BOTTOM, pady=5)
    
    def construir_taximetro_tab(self, parent):
        main_frame = tk.Frame(parent, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        estado_frame = tk.LabelFrame(main_frame, text="Estado del Viaje", padx=10, pady=10)
        estado_frame.pack(fill=tk.X, pady=5)
        
        self.estado_label = tk.Label(estado_frame, text="Viaje NO iniciado", font=("Arial", 12))
        self.estado_label.pack(pady=5)
        
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        self.btn_iniciar = tk.Button(btn_frame, text="Iniciar Viaje", width=15, 
                                    command=self.iniciar_viaje, bg="green", fg="white")
        self.btn_iniciar.grid(row=0, column=0, padx=5)
        
        self.btn_detenido = tk.Button(btn_frame, text="Detenido (P)", width=15, 
                                     command=partial(self.cambiar_estado, 'p'), state=tk.DISABLED)
        self.btn_detenido.grid(row=0, column=1, padx=5)
        
        self.btn_movimiento = tk.Button(btn_frame, text="Movimiento (M)", width=15, 
                                       command=partial(self.cambiar_estado, 'm'), state=tk.DISABLED)
        self.btn_movimiento.grid(row=0, column=2, padx=5)
        
        self.btn_finalizar = tk.Button(btn_frame, text="Finalizar (F)", width=15, 
                                      command=self.finalizar_viaje, state=tk.DISABLED, bg="red", fg="white")
        self.btn_finalizar.grid(row=0, column=3, padx=5)
        
        tarifas_frame = tk.LabelFrame(main_frame, text="Tarifas Actuales", padx=10, pady=10)
        tarifas_frame.pack(fill=tk.X, pady=5)
        
        self.tarifa_detencion_var = tk.StringVar(value=f"{self.taximetro.tarifas['detencion']}€/seg")
        self.tarifa_movimiento_var = tk.StringVar(value=f"{self.taximetro.tarifas['movimiento']}€/seg")
        
        tk.Label(tarifas_frame, text="Detención:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        tk.Label(tarifas_frame, textvariable=self.tarifa_detencion_var).grid(row=0, column=1, sticky="w", pady=2)
        
        tk.Label(tarifas_frame, text="Movimiento:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        tk.Label(tarifas_frame, textvariable=self.tarifa_movimiento_var).grid(row=1, column=1, sticky="w", pady=2)
        
        log_frame = tk.LabelFrame(main_frame, text="Bitácora del Sistema", padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.agregar_log("Sistema iniciado")
    
    def construir_admin_tab(self, parent):
        main_frame = tk.Frame(parent, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tarifas_frame = tk.LabelFrame(main_frame, text="Configuración de Tarifas", padx=10, pady=10)
        tarifas_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(tarifas_frame, text="Tarifa por Detención (€/seg):").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.nueva_detencion_var = tk.DoubleVar(value=self.taximetro.tarifas['detencion'])
        entry_detencion = tk.Entry(tarifas_frame, textvariable=self.nueva_detencion_var, width=10)
        entry_detencion.grid(row=0, column=1, pady=5, sticky="w")
        
        tk.Label(tarifas_frame, text="Tarifa por Movimiento (€/seg):").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.nueva_movimiento_var = tk.DoubleVar(value=self.taximetro.tarifas['movimiento'])
        entry_movimiento = tk.Entry(tarifas_frame, textvariable=self.nueva_movimiento_var, width=10)
        entry_movimiento.grid(row=1, column=1, pady=5, sticky="w")
        
        btn_actualizar = tk.Button(tarifas_frame, text="Actualizar Tarifas", 
                                  command=self.actualizar_tarifas)
        btn_actualizar.grid(row=2, column=0, columnspan=2, pady=10)
        
        password_frame = tk.LabelFrame(main_frame, text="Cambiar Mi Contraseña", padx=10, pady=10)
        password_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(password_frame, text="Nueva Contraseña:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.nueva_password_personal_entry = tk.Entry(password_frame, show="*", width=20)
        self.nueva_password_personal_entry.grid(row=0, column=1, pady=2, sticky="w")
        
        tk.Label(password_frame, text="Confirmar Contraseña:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.confirmar_password_personal_entry = tk.Entry(password_frame, show="*", width=20)
        self.confirmar_password_personal_entry.grid(row=1, column=1, pady=2, sticky="w")
        
        btn_cambiar_password = tk.Button(password_frame, text="Cambiar Contraseña", 
                                       command=self.cambiar_password_personal)
        btn_cambiar_password.grid(row=2, column=0, columnspan=2, pady=10)
        
        requisitos_frame = tk.LabelFrame(main_frame, text="Requisitos de Contraseña", padx=10, pady=10)
        requisitos_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(requisitos_frame, text="- Mínimo 8 caracteres", justify="left").pack(anchor="w")
        tk.Label(requisitos_frame, text="- Al menos una letra mayúscula y una minúscula", justify="left").pack(anchor="w")
        tk.Label(requisitos_frame, text="- Al menos un número", justify="left").pack(anchor="w")
        tk.Label(requisitos_frame, text="- Al menos un carácter especial (!@#$%^&*)", justify="left").pack(anchor="w")
    
    def construir_usuarios_tab(self, parent):
        main_frame = tk.Frame(parent, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        usuarios_frame = tk.LabelFrame(main_frame, text="Usuarios Registrados", padx=10, pady=10)
        usuarios_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        header_frame = tk.Frame(usuarios_frame)
        header_frame.pack(fill=tk.X)
        
        tk.Label(header_frame, text="Usuario", width=15, anchor="w", font=("Arial", 9, "bold")).pack(side="left", padx=5)
        tk.Label(header_frame, text="Rol", width=10, anchor="w", font=("Arial", 9, "bold")).pack(side="left", padx=5)
        tk.Label(header_frame, text="Acciones", width=20, anchor="w", font=("Arial", 9, "bold")).pack(side="left", padx=5)
        
        canvas = tk.Canvas(usuarios_frame)
        scrollbar = tk.Scrollbar(usuarios_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill=tk.BOTH, expand=True)
        scrollbar.pack(side="right", fill=tk.Y)
        
        self.usuarios_widgets = []
        for usuario in self.autenticador.listar_usuarios():
            self.agregar_usuario_a_lista(scrollable_frame, usuario)
        
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Agregar Nuevo Usuario", 
                 command=self.mostrar_ventana_agregar_usuario).pack(pady=5)
    
    def agregar_usuario_a_lista(self, parent, usuario):
        info = self.autenticador.obtener_info_usuario(usuario)
        if not info:
            return
        
        frame = tk.Frame(parent)
        frame.pack(fill=tk.X, pady=2)
        
        lbl_usuario = tk.Label(frame, text=usuario, width=15, anchor="w")
        lbl_usuario.pack(side="left", padx=5)
        
        rol = "Administrador" if info['es_admin'] else "Usuario"
        lbl_rol = tk.Label(frame, text=rol, width=10, anchor="w")
        lbl_rol.pack(side="left", padx=5)
        
        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="left", padx=5)
        
        btn_editar = tk.Button(btn_frame, text="Editar", width=8, 
                              command=partial(self.mostrar_ventana_editar_usuario, usuario))
        btn_editar.pack(side="left", padx=2)
        
        btn_eliminar = tk.Button(btn_frame, text="Eliminar", width=8, 
                                command=partial(self.eliminar_usuario, usuario))
        btn_eliminar.pack(side="left", padx=2)
        
        self.usuarios_widgets.append({
            'usuario': usuario,
            'frame': frame,
            'lbl_usuario': lbl_usuario,
            'lbl_rol': lbl_rol
        })
    
    def mostrar_ventana_agregar_usuario(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("Agregar Nuevo Usuario")
        ventana.geometry("400x300")
        ventana.grab_set()
        
        tk.Label(ventana, text="Nuevo Usuario:", font=("Arial", 10, "bold")).pack(pady=5)
        self.nuevo_usuario_var = tk.StringVar()
        entry_usuario = tk.Entry(ventana, textvariable=self.nuevo_usuario_var, width=25)
        entry_usuario.pack(pady=5)
        entry_usuario.focus()
        
        tk.Label(ventana, text="Contraseña:", font=("Arial", 10, "bold")).pack(pady=5)
        self.nueva_password_usuario_entry = tk.Entry(ventana, show="*", width=25)
        self.nueva_password_usuario_entry.pack(pady=5)
        
        tk.Label(ventana, text="Confirmar Contraseña:", font=("Arial", 10, "bold")).pack(pady=5)
        self.confirmar_password_usuario_entry = tk.Entry(ventana, show="*", width=25)
        self.confirmar_password_usuario_entry.pack(pady=5)
        
        self.es_admin_var = tk.BooleanVar()
        tk.Checkbutton(ventana, text="Es Administrador", variable=self.es_admin_var).pack(pady=10)
        
        btn_frame = tk.Frame(ventana)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Crear Usuario", 
                 command=self.crear_nuevo_usuario).pack(side="left", padx=10)
        
        tk.Button(btn_frame, text="Cancelar", 
                 command=ventana.destroy).pack(side="left", padx=10)
    
    def mostrar_ventana_editar_usuario(self, usuario):
        ventana = tk.Toplevel(self.root)
        ventana.title(f"Editar Usuario: {usuario}")
        ventana.geometry("400x350")
        ventana.grab_set()
        
        info = self.autenticador.obtener_info_usuario(usuario)
        if not info:
            ventana.destroy()
            return
        
        tk.Label(ventana, text="Nombre de Usuario:", font=("Arial", 10, "bold")).pack(pady=5)
        self.editar_usuario_var = tk.StringVar(value=usuario)
        entry_usuario = tk.Entry(ventana, textvariable=self.editar_usuario_var, width=25)
        entry_usuario.pack(pady=5)
        
        tk.Label(ventana, text="Nueva Contraseña (opcional):", font=("Arial", 10, "bold")).pack(pady=5)
        self.editar_password_entry = tk.Entry(ventana, show="*", width=25)
        self.editar_password_entry.pack(pady=5)
        
        tk.Label(ventana, text="Confirmar Contraseña:", font=("Arial", 10, "bold")).pack(pady=5)
        self.editar_confirmar_entry = tk.Entry(ventana, show="*", width=25)
        self.editar_confirmar_entry.pack(pady=5)
        
        self.editar_es_admin_var = tk.BooleanVar(value=info['es_admin'])
        tk.Checkbutton(ventana, text="Es Administrador", variable=self.editar_es_admin_var).pack(pady=10)
        
        btn_frame = tk.Frame(ventana)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Guardar Cambios", 
                 command=partial(self.guardar_cambios_usuario, usuario)).pack(side="left", padx=10)
        
        tk.Button(btn_frame, text="Cancelar", 
                 command=ventana.destroy).pack(side="left", padx=10)
    
    def crear_nuevo_usuario(self):
        nuevo_usuario = self.nuevo_usuario_var.get()
        password = self.nueva_password_usuario_entry.get()
        confirmacion = self.confirmar_password_usuario_entry.get()
        es_admin = self.es_admin_var.get()
        
        if not nuevo_usuario:
            messagebox.showerror("Error", "El nombre de usuario no puede estar vacío")
            return
        
        if password != confirmacion:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if not self.autenticador.validar_password(password):
            messagebox.showerror("Error", "La contraseña no cumple con los requisitos de seguridad")
            return
        
        exito, mensaje = self.autenticador.agregar_usuario(nuevo_usuario, password, es_admin)
        
        if exito:
            # Obtener el frame scrollable de la pestaña de usuarios
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Notebook):
                    for tab in widget.winfo_children():
                        if "usuarios" in str(tab):
                            scrollable_frame = tab.winfo_children()[0].winfo_children()[0].winfo_children()[0].winfo_children()[0]
                            self.agregar_usuario_a_lista(scrollable_frame, nuevo_usuario)
                            break
            messagebox.showinfo("Éxito", f"Usuario '{nuevo_usuario}' creado con éxito")
            self.nuevo_usuario_var.master.destroy()
        else:
            messagebox.showerror("Error", mensaje)
    
    def guardar_cambios_usuario(self, usuario_original):
        nuevo_usuario = self.editar_usuario_var.get()
        nueva_password = self.editar_password_entry.get()
        confirmacion = self.editar_confirmar_entry.get()
        nuevo_es_admin = self.editar_es_admin_var.get()
        
        if nueva_password and nueva_password != confirmacion:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if nueva_password and not self.autenticador.validar_password(nueva_password):
            messagebox.showerror("Error", "La nueva contraseña no cumple con los requisitos de seguridad")
            return
        
        exito, mensaje = self.autenticador.modificar_usuario(
            usuario_original,
            nuevo_usuario if nuevo_usuario != usuario_original else None,
            nueva_password if nueva_password else None,
            nuevo_es_admin
        )
        
        if exito:
            # Actualizar lista de usuarios
            for widget in self.usuarios_widgets[:]:
                if widget['usuario'] == usuario_original:
                    widget['frame'].destroy()
                    self.usuarios_widgets.remove(widget)
                    break
            
            # Obtener el frame scrollable de la pestaña de usuarios
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Notebook):
                    for tab in widget.winfo_children():
                        if "usuarios" in str(tab):
                            scrollable_frame = tab.winfo_children()[0].winfo_children()[0].winfo_children()[0].winfo_children()[0]
                            self.agregar_usuario_a_lista(scrollable_frame, nuevo_usuario)
                            break
            
            # Si el usuario actual se cambió a sí mismo, actualizar estado
            if self.usuario_actual == usuario_original:
                self.usuario_actual = nuevo_usuario
                self.status_var.set(f"Usuario: {self.usuario_actual} | {'(Admin)' if self.autenticador.es_admin(self.usuario_actual) else ''}")
            
            messagebox.showinfo("Éxito", f"Usuario '{nuevo_usuario}' actualizado con éxito")
            self.editar_usuario_var.master.destroy()
        else:
            messagebox.showerror("Error", mensaje)
    
    def eliminar_usuario(self, usuario):
        if usuario == self.usuario_actual:
            messagebox.showerror("Error", "No puede eliminarse a sí mismo")
            return
        
        if not messagebox.askyesno("Confirmar", f"¿Está seguro que desea eliminar al usuario '{usuario}'?"):
            return
        
        exito, mensaje = self.autenticador.eliminar_usuario(usuario)
        
        if exito:
            # Eliminar de la lista visual
            for widget in self.usuarios_widgets[:]:
                if widget['usuario'] == usuario:
                    widget['frame'].destroy()
                    self.usuarios_widgets.remove(widget)
                    break
            messagebox.showinfo("Éxito", f"Usuario '{usuario}' eliminado con éxito")
        else:
            messagebox.showerror("Error", mensaje)
    
    def actualizar_tarifas(self):
        try:
            detencion = float(self.nueva_detencion_var.get())
            movimiento = float(self.nueva_movimiento_var.get())
            
            if detencion <= 0 or movimiento <= 0:
                raise ValueError("Las tarifas deben ser mayores a cero")
        except ValueError as e:
            messagebox.showerror("Error", f"Valor inválido: {str(e)}")
            return
        
        if self.taximetro.actualizar_tarifas(detencion, movimiento):
            self.tarifa_detencion_var.set(f"{detencion}€/seg")
            self.tarifa_movimiento_var.set(f"{movimiento}€/seg")
            messagebox.showinfo("Éxito", "Tarifas actualizadas correctamente")
            self.agregar_log("Tarifas actualizadas")
        else:
            messagebox.showerror("Error", "No se pudieron actualizar las tarifas")
    
    def cambiar_password_personal(self):
        nueva_password = self.nueva_password_personal_entry.get()
        confirmacion = self.confirmar_password_personal_entry.get()
        
        if nueva_password != confirmacion:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if not self.autenticador.validar_password(nueva_password):
            messagebox.showerror("Error", "La contraseña no cumple con los requisitos de seguridad")
            return
        
        exito, mensaje = self.autenticador.modificar_usuario(
            self.usuario_actual, 
            nueva_password=nueva_password
        )
        
        if exito:
            messagebox.showinfo("Éxito", "Contraseña cambiada con éxito")
            self.nueva_password_personal_entry.delete(0, tk.END)
            self.confirmar_password_personal_entry.delete(0, tk.END)
            self.agregar_log("Contraseña personal cambiada")
        else:
            messagebox.showerror("Error", mensaje)
    
    def limpiar_interfaz(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def iniciar_viaje(self):
        self.taximetro.iniciar_viaje()
        self.viaje_activo = True
        self.estado_label.config(text="Viaje INICIADO - Estado: Ninguno")
        
        self.btn_detenido.config(state=tk.NORMAL)
        self.btn_movimiento.config(state=tk.NORMAL)
        self.btn_finalizar.config(state=tk.NORMAL)
        self.btn_iniciar.config(state=tk.DISABLED)
        
        self.agregar_log("Viaje iniciado")
    
    def cambiar_estado(self, estado):
        if not self.viaje_activo:
            return
            
        self.taximetro.actualizar_estado(estado)
        estado_text = "DETENIDO" if estado == 'p' else "EN MOVIMIENTO"
        self.estado_label.config(text=f"Viaje ACTIVO - Estado: {estado_text}")
        
        self.agregar_log("Taxi detenido" if estado == 'p' else "Taxi en movimiento")
    
    def finalizar_viaje(self):
        if not self.viaje_activo:
            return
            
        resumen = self.taximetro.finalizar_viaje()
        self.viaje_activo = False
        
        self.btn_detenido.config(state=tk.DISABLED)
        self.btn_movimiento.config(state=tk.DISABLED)
        self.btn_finalizar.config(state=tk.DISABLED)
        self.btn_iniciar.config(state=tk.NORMAL)
        
        self.estado_label.config(text="Viaje FINALIZADO")
        self.agregar_log("Viaje finalizado")
        
        messagebox.showinfo("Resumen del Viaje", 
                          f"Total por detenciones: {resumen['detenido']:.2f}€\n"
                          f"Total por movimiento: {resumen['movimiento']:.2f}€\n"
                          f"TARIFA TOTAL: {resumen['total']:.2f}€")
    
    def agregar_log(self, mensaje):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {mensaje}\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
    
    def cerrar_sesion(self):
        self.usuario_actual = None
        self.viaje_activo = False
        self.crear_interfaz_login()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='taximetro.log',
        filemode='a'
    )
    
    configurador = Configurador()
    autenticador = Autenticador()
    taximetro = Taximetro(configurador)
    
    root = tk.Tk()
    app = TaximetroGUI(root, taximetro, autenticador, configurador)
    root.mainloop()
