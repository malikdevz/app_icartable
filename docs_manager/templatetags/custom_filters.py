from django import template

register = template.Library()

@register.filter
def cut_doc_title(value):
    if len(value) > 30:
        return value[:30]+"..."
    else:
        return value