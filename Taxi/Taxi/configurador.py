from helpers import cargar_json_seguro, guardar_json_seguro

class Configurador:
    def __init__(self, archivo_config='config.json'):
        self.archivo_config = archivo_config
        self.config = cargar_json_seguro(
            archivo_config,
            {
                'tarifas': {'detencion': 0.03, 'movimiento': 0.06},
                'primer_inicio': True
            }
        )
    
    def actualizar_tarifas(self, nueva_detencion, nuevo_movimiento):
        self.config['tarifas'].update({
            'detencion': nueva_detencion,
            'movimiento': nuevo_movimiento
        })
        return guardar_json_seguro(self.archivo_config, self.config)
    
    def marcar_primer_inicio_completado(self):
        self.config['primer_inicio'] = False
        return guardar_json_seguro(self.archivo_config, self.config)
