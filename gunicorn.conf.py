# 2 workers con HILOS (gthread) + preload_app: comparten el código por copy-on-write (entra en
# 512MB). Cada worker atiende VARIOS requests a la vez, así un /pf-periodo lento (I/O de red a
# TiendaNube/MercadoPago) libera el GIL mientras espera y NO tapa al resto: la página y los
# endpoints livianos (/pf-version, etc.) siguen respondiendo. Evita la saturación total (todo 502/timeout).
workers = 2
worker_class = "gthread"
threads = 8                 # 2 workers x 8 hilos = 16 requests concurrentes
preload_app = True
timeout = 120
graceful_timeout = 30
max_requests = 400          # recicla workers cada tanto para que no crezca la RAM
max_requests_jitter = 50
