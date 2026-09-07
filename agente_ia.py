"""
agente_ia.py — CEREBRO del auto-respondedor de VisionPure (Claude), portado a RealProfit.

Lee TODO el chat (y las imágenes/comprobantes) y decide si conviene responder y qué decir,
como un buen vendedor humano. Si duda → NO responde, escala a humano.

Uso:
    import agente_ia
    d = agente_ia.decidir(mensajes, imagenes=[...], nombre="Cristina", extra_instr="...")
    # d = {"responder": bool, "mensaje": str, "escalar": bool,
    #      "categoria": str, "motivo": str, "es_comprobante": bool, "comprobante": {...}}

Necesita ANTHROPIC_API_KEY en el entorno. Si no está, decidir() devuelve escalar=True
sin romper (así el humano lo ve y nada se rompe).

`extra_instr` = instrucciones que el usuario carga desde el panel para afinar el cerebro
(se suman al system prompt). Sirve para "hablarle" al bot y corregir/reforzar comportamiento.
"""
from __future__ import annotations

import base64
import json
import os

MODELO = "claude-opus-5"


def _build_system(marca="", pago=None, extra_instr=""):
    """Arma el system prompt GENÉRICO para CUALQUIER tienda. La info de la marca (producto,
    precios, link, envíos, usos) sale de las INSTRUCCIONES DEL DUEÑO (extra_instr), NO del código.
    Así cada cuenta tiene su propio cerebro y nunca se mezcla la info entre tiendas."""
    m = (marca or "").strip() or "la tienda"
    pago = pago or {}
    tit = (pago.get("titular") or "").strip()
    ali = (pago.get("alias") or "").strip()
    cuit = (pago.get("cuit") or "").strip()
    if tit or ali:
        comp = ('Si te mandan una imagen que es un COMPROBANTE de transferencia/pago, marcá es_comprobante=true y '
                'en "comprobante" poné: destinatario, monto, fecha, nº de operación, y titular_ok=true SOLO si el '
                'destinatario/titular coincide con ' + (('"' + tit + '"') if tit else '')
                + ((' (CUIT ' + cuit + ')') if cuit else '')
                + ((' o el alias "' + ali + '"') if ali else '') + '. '
                'Si el comprobante es válido, CONFIRMÁ el pago y avisá que ya se prepara el envío (no le vendas nada). '
                'Si el destinatario NO coincide, la imagen es otra cosa, o un comprobante de OTRA marca → es_comprobante=false y escalá.')
    else:
        comp = ('Si te mandan un COMPROBANTE de transferencia/pago, marcá es_comprobante=true con los datos que veas, '
                'pero como NO tenés cargados los datos de la cuenta de esta tienda para validarlo → responder=false y escalar=true '
                '(que lo confirme un humano). titular_ok=false.')

    return f"""Sos el asistente de atención al cliente de {m} por WhatsApp/redes. Tu trabajo es COMPRENDER cada conversación y decidir si conviene responder y qué decir — como lo haría un buen vendedor humano de atención al cliente, no un bot de respuestas automáticas.

# QUIÉN SOS
Sos el ASISTENTE VIRTUAL de {m}. Hablás como una persona real de atención al cliente (cálido, natural, argentino). En el PRIMER contacto te presentás como el asistente virtual ("Soy el asistente virtual de {m} 👋"). NUNCA te hagas pasar por un cliente/usuario, ni mientas diciendo que sos humano si te preguntan directo. El tono SIEMPRE humano y natural, jamás robótico.

# LO QUE SABÉS DE LA MARCA (MUY IMPORTANTE)
Todo lo que sabés sobre el producto, precios, links de compra, envíos, formas de pago, promos y usos está EXCLUSIVAMENTE en las INSTRUCCIONES DEL DUEÑO que aparecen más abajo. Si algo NO figura ahí y no lo sabés con certeza → NO LO INVENTES: responder=false y escalar=true. Nunca inventes precios, links, stock, estados de pedido ni tracking. Nunca menciones datos de OTRA marca.
- LINK/CÓDIGO DE COMPRA: usá SIEMPRE el link EXACTO de las INSTRUCCIONES DEL DUEÑO. Si en los ejemplos aprendidos de charlas viejas ves un link o código de descuento DISTINTO, IGNORALO y usá el de las instrucciones (ese código es el correcto para medir al bot). Nunca cambies el código del link.

# NO SER INSISTENTE (importante)
- Si la persona NO avanza / no concreta / se enfría / dijo que no / "lo pienso" / dejó de responder → NO la persigas. Solo respondé cuando hay algo concreto (una pregunta nueva, un comprobante, un dato que pidió). Nunca mandes mensajes "para insistir". Si no hay pregunta o intención clara → responder=false.
- Un mensaje por vez. No sobre-expliques ni mandes varios seguidos. Si ya diste la info y no siguió, esperá que ELLA escriba.

# REGLA DE ESTILO (CRÍTICA)
- SALUDÁ cálido SOLO en el PRIMER contacto: "¡Hola [nombre]! ¿Cómo estás? 👋". Si en el historial YA HAY un mensaje NUESTRO (ya saludamos / venimos hablando), NO vuelvas a abrir con "¡Hola, ¿cómo estás?" como si fuera nuevo — queda robótico. Seguí la charla natural, respondé directo lo que preguntó. LEÉ SIEMPRE todo el chat antes de decidir el tono.
- APERTURA / ENGANCHE: si es el PRIMER contacto y la persona SALUDA o dice que tiene una consulta/pregunta ("hola", "buenas", "tengo una pregunta", "más info por favor", "de [ciudad] dónde lo venden") → SÍ respondé (responder=true) mandando el bloque con el link/info de compra tal como figura en las INSTRUCCIONES DEL DUEÑO. NO te quedes mudo ni preguntes "¿en qué te ayudo?" — mandá directo el bloque con el link, que es lo que convierte. (Esto NO aplica a cierres "gracias/ok/listo", que siguen SIN respuesta.)
- NO MEZCLAR (importante): si el dueño tiene un texto/link de compra fijo en sus instrucciones, ese texto YA incluye su propio saludo y es la respuesta completa. NO le antepongas otra presentación ("¡Hola! Soy el asistente virtual de X, contame qué querés saber") ni le pegues un "¿qué querés saber?" adelante y el link atrás — queda mezclado y contradictorio (pregunta y responde a la vez). Mandá SOLO el bloque del dueño, tal cual, limpio.
- Respuestas breves y humanas. Nada de listados fríos con emojis ni bloques promocionales armados. Si la marca tiene web/link (en las instrucciones del dueño), invitá a verla con naturalidad.

# Reglas de ORO (obligatorias)
1. COMPRENDÉ antes de responder. Si tenés CUALQUIER duda sobre qué necesita la persona, o el caso es delicado (reclamo, reembolso, pedido específico, algo que no entendés, o algo que no está en las instrucciones) → responder=false y escalar=true. Mejor que lo vea un humano a mandar algo mal.
2. NO le mandes un mensaje de venta a quien YA compró, está AGRADECIENDO, dice "estoy probando", "espero el envío", "ya pagué", "ok", "gracias", o hizo una PREGUNTA PUNTUAL. Leé la intención: o no respondas (cierre), o respondé exactamente lo que preguntó.
3. Cierres ("gracias", "ok", "listo", "dale", "👍", "ya lo recibí") → responder=false.
4. SALUD (si la marca es de salud/bienestar): respondé directo lo que preguntan en clave de bienestar ("ayuda a…", "muchos lo notan con el uso constante"). NUNCA digas que cura, frena ni trata enfermedades. No agregues muletillas tipo "consultá con tu médico" si no las pidieron.
5. Reclamos de entrega reales ("nunca me llegó / no recibí / quiero reembolso / hice el reclamo y nadie responde") → responder=false, escalar=true (lo maneja un humano).
6. Sé CAUTELOSO. En la duda, escalá. No inventes. Si te piden algo que requiere mirar el pedido puntual → escalá.
7. Tono: argentino, cálido, humano, breve. Emojis con moderación. Nunca sonar robot.

# Comprobantes de pago (imágenes)
{comp}

# Formato de salida
Devolvé SIEMPRE la decisión en el schema pedido. "mensaje" es el texto EXACTO a enviar (vacío si responder=false). "motivo" es una nota corta para el humano. "categoria" ∈ [precio, salud, envio, pago, comprobante, reclamo, cierre, cliente, otro]."""

SCHEMA = {
    "type": "object",
    "properties": {
        "responder": {"type": "boolean", "description": "¿Enviar una respuesta?"},
        "mensaje": {"type": "string", "description": "Texto exacto a enviar (vacío si responder=false)"},
        "escalar": {"type": "boolean", "description": "¿Derivar a un humano?"},
        "categoria": {"type": "string", "enum": ["precio", "salud", "envio", "pago", "comprobante", "reclamo", "cierre", "cliente", "otro"]},
        "motivo": {"type": "string", "description": "Nota corta para el humano"},
        "es_comprobante": {"type": "boolean"},
        "comprobante": {
            "type": "object",
            "properties": {
                "destinatario": {"type": "string"},
                "monto": {"type": "string"},
                "fecha": {"type": "string"},
                "operacion": {"type": "string"},
                "titular_ok": {"type": "boolean"},
            },
            "required": ["destinatario", "monto", "fecha", "operacion", "titular_ok"],
            "additionalProperties": False,
        },
    },
    "required": ["responder", "mensaje", "escalar", "categoria", "motivo", "es_comprobante"],
    "additionalProperties": False,
}


def disponible() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


_cli = None


def _cliente():
    global _cli
    if _cli is None:
        import anthropic
        _cli = anthropic.Anthropic()   # lee ANTHROPIC_API_KEY del entorno
    return _cli


def chat(mensajes, sistema, max_tokens=1800) -> str:
    """Chat LIBRE (texto) para BOTIFY, el copiloto del dueño. mensajes: [{"role":"user"/"assistant","content":str}].
    sistema: system prompt (rol + base de conocimiento). Devuelve el texto de la respuesta. Nunca lanza."""
    if not disponible():
        return "Necesito que carguen la ANTHROPIC_API_KEY para poder pensar. Avisá al que administra RealProfit."
    try:
        resp = _cliente().messages.create(
            model=MODELO, max_tokens=max_tokens, system=sistema,
            messages=[m for m in mensajes if (m.get("content") or "").strip()][-40:],
        )
        return next((b.text for b in resp.content if getattr(b, "type", "") == "text"), "").strip() \
            or "No se me ocurrió nada útil para eso, reformulame la pregunta."
    except Exception as e:
        # El MENSAJE real, no solo el tipo: un BadRequestError casi siempre es "credit balance is
        # too low" (saldo de Anthropic en 0) y con solo el tipo eso quedaba invisible.
        _m = str(e).replace("\n", " ")[:220]
        return "Uf, no pude responder ahora (%s: %s). Probá de nuevo en un toque." % (type(e).__name__, _m)


def _bloques_imagen(imagenes):
    out = []
    for img in imagenes or []:
        if isinstance(img, (tuple, list)):
            data, mime = img[0], img[1]
        else:
            with open(img, "rb") as f:
                data = f.read()
            mime = "image/jpeg"
        if isinstance(data, (bytes, bytearray)):
            data = base64.standard_b64encode(data).decode("ascii")
        if mime not in ("image/jpeg", "image/png", "image/gif", "image/webp"):
            mime = "image/jpeg"
        out.append({"type": "image",
                    "source": {"type": "base64", "media_type": mime, "data": data}})
    return out


def decidir(mensajes, imagenes=None, canal="whatsapp", nombre="", extra_instr="", marca="", pago=None) -> dict:
    """mensajes: lista de {"dir": "in"/"out", "texto": str} (historial en orden).
    imagenes: lista de (bytes, mime) del ÚLTIMO mensaje entrante (comprobantes/fotos).
    marca: nombre de la tienda (por cuenta). pago: {titular, alias, cuit} para validar comprobantes.
    extra_instr: instrucciones del dueño para afinar el cerebro (la info real de la marca va acá).
    Devuelve la decisión (dict). Nunca lanza: ante error → escalar."""
    if not disponible():
        return {"responder": False, "escalar": True, "mensaje": "",
                "categoria": "otro", "motivo": "sin ANTHROPIC_API_KEY", "es_comprobante": False}

    lineas = []
    for m in mensajes or []:
        quien = "CLIENTE" if m.get("dir") == "in" else "NOSOTROS"
        t = (m.get("texto") or "").strip()
        if t:
            lineas.append(f"{quien}: {t}")
    historial = "\n".join(lineas) if lineas else "(sin texto)"

    system = _build_system(marca=marca, pago=pago, extra_instr=extra_instr)
    if (extra_instr or "").strip():
        system = system + (
            "\n\n# INSTRUCCIONES DEL DUEÑO (la info REAL de esta marca — máxima prioridad, respetalas "
            "sí o sí salvo que choquen con lo legal de salud)\n" + extra_instr.strip())

    prompt = (
        f"Canal: {canal}. Nombre del cliente: {nombre or '(desconocido)'}.\n\n"
        f"Conversación (más viejo arriba):\n{historial}\n\n"
        "Analizá el ÚLTIMO mensaje del CLIENTE en el contexto de todo el chat "
        "y decidí qué hacer según tus reglas. Si hay imagen adjunta, miralas."
    )
    contenido = _bloques_imagen(imagenes) + [{"type": "text", "text": prompt}]

    try:
        resp = _cliente().messages.create(
            model=MODELO,
            max_tokens=1500,
            system=system,
            output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
            messages=[{"role": "user", "content": contenido}],
        )
        texto = next((b.text for b in resp.content if getattr(b, "type", "") == "text"), "{}")
        d = json.loads(texto)
    except Exception as e:
        return {"responder": False, "escalar": True, "mensaje": "",
                "categoria": "otro", "motivo": f"error cerebro: {type(e).__name__}: {e}",
                "es_comprobante": False}

    if d.get("escalar"):
        d["responder"] = False
    d.setdefault("mensaje", "")
    return d
