from django.shortcuts import render
from .kratos_auth import kratos_login_required
from django.http import JsonResponse
from .models import Book
# Create your views here.

def books_list(request):
    books = Book.objects.all()
    data = [{'title': b.title, 'author': b.author, 'year': b.year} for b in books]
    return JsonResponse(data, safe=False)

def mongo_test(request):
    # Crea un documento di test
    book = Book(title="Test Book", author="Test Author", year=2025)
    book.save()

    # Recupera tutti i libri
    books = Book.objects.all()
    data = [{'title': b.title, 'author': b.author, 'year': b.year} for b in books]
    return JsonResponse({'books': data})

@kratos_login_required
def secret_data(request):
    user_traits = request.kratos_session['identity']['traits']
    return JsonResponse({
        'msg': f"Ciao {user_traits.get('email', 'utente')}! Questa è una view protetta.",
        'traits': user_traits
    })