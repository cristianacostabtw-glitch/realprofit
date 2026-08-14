# Gunicorn carga ESTE archivo automáticamente si está en la carpeta del app y el comando de
# arranque no pasa -c. Por eso NO hace falta tocar el "Start Command" en el panel de Render:
# con solo subir este archivo, el server pasa de 1 hilo a 8.
#
# El problema: el server atendía 1 request POR VEZ (1 worker / 1 hilo). Al entrar, el dashboard
# hace ~6 llamadas (pf-periodo, mp/estado, shopify/estado, recompras, ventas...) y se atendían
# en fila; una lenta trababa TODAS (hasta el /login timeouteaba). Con 8 hilos atiende 8 a la vez
# → carga en segundos.

workers = 1        # 1 solo proceso → la caché en memoria queda compartida y coherente
threads = 8        # 8 requests en paralelo por proceso (ideal para I/O: TN/MP/Meta/Shopify)
timeout = 120      # una request larga no mata al worker
graceful_timeout = 30
