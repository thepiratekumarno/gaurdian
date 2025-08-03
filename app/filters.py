from jinja2 import Environment

def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

def init_filters(env: Environment):
    env.filters['datetimeformat'] = datetimeformat
