from django import template

register = template.Library()

@register.filter
def short_hash(value):
    """Return first 5 + '.....' + last 5 characters of a long string."""
    if not value:
        return value
    if len(value) <= 12:
        return value
    return f"{value[:10]}.....{value[-10:]}"
