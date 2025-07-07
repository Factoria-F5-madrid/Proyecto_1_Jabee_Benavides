from helpers import cargar_json_seguro, guardar_json_seguro, hash_password, validar_password as validar_externo


class Autenticador:
    def __init__(self, archivo_credenciales='credenciales.secure'):
        self.archivo_credenciales = archivo_credenciales
        self.credenciales = cargar_json_seguro(
            archivo_credenciales,
            {
                'admin': {
                    'hash': hash_password('1234'),
                    'es_admin': True
                }
            }
        )
    
    def autenticar(self, usuario, password):
        return usuario in self.credenciales and \
               self.credenciales[usuario]['hash'] == hash_password(password)
    
    def es_admin(self, usuario):
        return self.credenciales.get(usuario, {}).get('es_admin', False)
    
    def validar_password(self, password):
        return validar_externo(password)

    def agregar_usuario(self, usuario, password, es_admin=False):
        if usuario in self.credenciales:
            return False, "El usuario ya existe"
        
        if not self.validar_password(password):
            return False, "La contraseña no cumple con los requisitos"
        
        self.credenciales[usuario] = {
            'hash': hash_password(password),
            'es_admin': es_admin
        }
        return self._guardar_credenciales()
    
    def modificar_usuario(self, usuario, nuevo_usuario=None, nueva_password=None, nuevo_es_admin=None):
        if usuario not in self.credenciales:
            return False, "El usuario no existe"
        
        if self.credenciales[usuario]['es_admin'] and nuevo_es_admin is False:
            if sum(1 for u in self.credenciales.values() if u['es_admin']) <= 1:
                return False, "No se puede quitar el rol al último admin"
        
        if nuevo_usuario and nuevo_usuario != usuario:
            if nuevo_usuario in self.credenciales:
                return False, "El nuevo usuario ya existe"
            self.credenciales[nuevo_usuario] = self.credenciales.pop(usuario)
            usuario = nuevo_usuario
        
        if nueva_password:
            if not self.validar_password(nueva_password):
                return False, "La nueva contraseña no es válida"
            self.credenciales[usuario]['hash'] = hash_password(nueva_password)
        
        if nuevo_es_admin is not None:
            self.credenciales[usuario]['es_admin'] = nuevo_es_admin
        
        return self._guardar_credenciales()
    
    def eliminar_usuario(self, usuario):
        if usuario not in self.credenciales:
            return False, "El usuario no existe"
        
        if self.credenciales[usuario]['es_admin']:
            if sum(1 for u in self.credenciales.values() if u['es_admin']) <= 1:
                return False, "No se puede eliminar al último admin"
        
        del self.credenciales[usuario]
        return self._guardar_credenciales()
    
    def _guardar_credenciales(self):
        return guardar_json_seguro(self.archivo_credenciales, self.credenciales), "Operación realizada"
    
    def listar_usuarios(self):
        return list(self.credenciales.keys())
    
    def obtener_info_usuario(self, usuario):
        return self.credenciales.get(usuario)

