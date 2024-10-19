from django.http import JsonResponse

class CustomResponseMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if hasattr(response, 'data'):
            return JsonResponse({
                'status':  response.status_code ,
                'message': response.data.get('message', ''),
                'data': response.data.get('data',{}),
            })
        return response
