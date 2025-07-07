import time
from datetime import datetime
import json
import logging
from helpers import calcular_tarifa

class Taximetro:
    def __init__(self, configurador):
        self.configurador = configurador
        self.tarifas = self.configurador.config['tarifas']
        self.historial_file = 'historial_viajes.txt'
        self.resetear_estado()
    
    def resetear_estado(self):
        self.total_detenido = 0.0
        self.total_movimiento = 0.0
        self.inicio_periodo = time.time()
        self.estado_actual = None
    
    def iniciar_viaje(self):
        self.resetear_estado()
        logging.info("Viaje iniciado")
    
    def actualizar_estado(self, nuevo_estado):
        tiempo_actual = time.time()
        tiempo_transcurrido = tiempo_actual - self.inicio_periodo
        
        if self.estado_actual == 'p':
            self.total_detenido += tiempo_transcurrido * self.tarifas['detencion']
        elif self.estado_actual == 'm':
            self.total_movimiento += tiempo_transcurrido * self.tarifas['movimiento']
        
        self.estado_actual = nuevo_estado
        self.inicio_periodo = tiempo_actual
    
    def finalizar_viaje(self):
        self.actualizar_estado(None)
        total_tarifa = calcular_tarifa(
            self.tarifas['detencion'],
            self.tarifas['movimiento'],
            self.total_detenido,
            self.total_movimiento
        )
        
        resumen = {
            'fecha': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'detenido': round(self.total_detenido, 2),
            'movimiento': round(self.total_movimiento, 2),
            'total': total_tarifa
        }
        
        try:
            with open(self.historial_file, 'a') as f:
                f.write(json.dumps(resumen) + '\n')
            logging.info(f"Viaje finalizado. Total: {total_tarifa:.2f}€")
        except Exception as e:
            logging.error(f"Error guardando historial: {str(e)}")
        
        return resumen
    
    def actualizar_tarifas(self, detencion, movimiento):
        self.tarifas.update({
            'detencion': detencion,
            'movimiento': movimiento
        })
        return self.configurador.actualizar_tarifas(detencion, movimiento)
