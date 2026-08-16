# 2 workers SYNC con preload_app: comparten el código por copy-on-write (entra en 512MB) y dan
# CONCURRENCIA. Así un /pf-periodo lento NO tapa todo: el otro worker sigue sirviendo la página
# y los endpoints livianos (se evita el 502 por saturación del worker único).
workers = 2
preload_app = True
timeout = 120
max_requests = 400          # recicla workers cada tanto para que no crezca la RAM
max_requests_jitter = 50
