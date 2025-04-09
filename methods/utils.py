import json, os, argparse



def cleanUselessStuffFromDict(dict):
    for item in dict:
        item['subdomain'].pop('id')
    return dict

def prettyPrintJSON(dict):
    return json.dumps(dict, indent=4)


def cleanUselessStuffFromDict(dict, keys):
    cleaned = [dict.pop(key) for key in keys]
    return cleaned

def normalize_filename(filename, extension):
    # Asegurarse de que la extensión comience con un punto
    if not extension.startswith('.'):
        extension = f'.{extension}'
    
    # Separar el nombre base y la extensión actual del archivo
    base, ext = os.path.splitext(filename)
    
    # Si la extensión actual no coincide con la deseada, reemplazarla
    if ext.lower() != extension.lower():
        return f"{base}{extension}"
    else:
        return filename

def parse_filters(value):
    """
    Parsear los filtros proporcionados, separados por comas, y validar las opciones.

    :param value: Cadena de filtros separados por comas (e.g., "medium,high,critical")
    :return: Lista de filtros válidos sin duplicados (e.g., ["medium", "high", "critical"])
    :raises argparse.ArgumentTypeError: Si se proporciona un filtro inválido.
    """
    allowed_filters = {'info', 'low', 'medium', 'high', 'critical'}
    # Dividir la cadena por comas y eliminar espacios en blanco
    filters = [filtro.strip().lower() for filtro in value.split(',') if filtro.strip()]
    
    # Identificar filtros inválidos
    invalid_filters = set(filters) - allowed_filters
    if invalid_filters:
        raise argparse.ArgumentTypeError(
            f"Filtros inválidos: {', '.join(invalid_filters)}. "
            f"Opciones válidas son: {', '.join(allowed_filters)}."
        )
    
    # Eliminar duplicados manteniendo el orden
    seen = set()
    unique_filters = []
    for filtro in filters:
        if filtro not in seen:
            unique_filters.append(filtro)
            seen.add(filtro)
    
    return unique_filters