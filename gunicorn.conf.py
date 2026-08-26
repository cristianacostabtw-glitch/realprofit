# 1 worker con HILOS (gthread). CLAVE: un solo proceso = UNA sola cache (_PF_CACHE, gasto de Meta,
# etc.) → el dashboard NO parpadea entre valores distintos (con 2 workers cada uno tenía su propio
# snapshot y al alternar los requests los números saltaban). Los hilos dan concurrencia: un
# /pf-periodo lento (I/O a TiendaNube/MercadoPago) libera el GIL mientras espera y NO tapa al resto,
# así se evita la saturación total sin necesidad de un segundo worker (que rompía la consistencia).
workers = 1
worker_class = "gthread"
threads = 20                # 1 worker x 20 hilos: más headroom → operaciones lentas de Shopify (seguimiento) NO saturan
preload_app = True
timeout = 75                # antes 120: si un request se traba, el hilo se recicla en 75s (no cuelga 2 min al resto)
graceful_timeout = 30
max_requests = 800          # recicla el worker cada tanto para que no crezca la RAM
max_requests_jitter = 100
