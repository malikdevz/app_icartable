from django import template

register = template.Library()

@register.filter
def cut_doc_title(value):
    if len(value) > 45:
        return value[:40]+"..."
    else:
        return value