#!/usr/bin/env python3
"""Proyección transparente del benchmark externo al caso PBKDF2-200k."""

import math

HASHCAT_4090_HPS_AT_999 = 8_865.7 * 1_000
BENCHMARK_ITERATIONS = 999
LAB_ITERATIONS = 200_000
GPU_COUNT = 1_000
DICTIONARY_SIZE = 49

hps_one_gpu = HASHCAT_4090_HPS_AT_999 * BENCHMARK_ITERATIONS / LAB_ITERATIONS
hps_fleet = hps_one_gpu * GPU_COUNT
single_gpu_seconds = DICTIONARY_SIZE / hps_one_gpu
one_attempt_latency_seconds = 1 / hps_one_gpu
active_workers = min(GPU_COUNT, DICTIONARY_SIZE)
parallel_batches = math.ceil(DICTIONARY_SIZE / active_workers)
fleet_wall_seconds = parallel_batches * one_attempt_latency_seconds

print("PBKDF2-HMAC-SHA256, proyección ideal a 200000 iteraciones")
print(f"Hashcat RTX 4090 fuente: {HASHCAT_4090_HPS_AT_999:,.0f} intentos/s @ {BENCHMARK_ITERATIONS} iteraciones")
print(f"Regla de escala usada: velocidad proporcional a 1/iteraciones")
print(f"Estimación por RTX 4090: {hps_one_gpu:,.2f} intentos/s")
print(f"1000 RTX 4090, escala lineal ideal: {hps_fleet:,.0f} intentos/s")
print(f"Diccionario: {DICTIONARY_SIZE} candidatos")
print(f"Tiempo de cálculo con 1 GPU: {single_gpu_seconds:.9f} s")
print(f"Latencia estimada de una verificación por GPU: {one_attempt_latency_seconds:.9f} s")
print(f"GPU activas para {DICTIONARY_SIZE} candidatos: {active_workers}")
print(f"Lotes paralelos necesarios: {parallel_batches}")
print(f"Tiempo ideal del diccionario con la flota: {fleet_wall_seconds:.9f} s")
print("No se divide la cantidad de candidatos por la flota completa: con 49")
print("candidatos, solo 49 GPUs pueden verificar uno cada una en el primer lote.")
print("La proyección no es una ejecución de 1000 GPUs ni una medición directa a 200000 iteraciones.")
