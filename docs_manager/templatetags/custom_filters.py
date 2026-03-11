from django import template

register = template.Library()

@register.filter
def cut_doc_title(value):
    if len(value) > 20:
        return value[:20]+"..."
    else:
        return value