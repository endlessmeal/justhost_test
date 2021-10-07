from django.http import HttpResponse
from .utils import get_domains, get_abuses


def domains(request):
    return HttpResponse(get_domains())


def abuses(request, status='active', ip=None, domain=None):
    return HttpResponse(get_abuses(status, ip, domain))
