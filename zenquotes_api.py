from requests import get

URL = 'https://zenquotes.io/api/quotes/'


def get_quote():
    response = get(url=URL)
    data = response.json()[0]
    quote = data['q']
    author = data['a']
    if quote == 'Unrecognized API request. Visit zenquotes.io for documentation.':
        quote = 'Service currently unavailable. Try again later!'
        author = False
    return quote, author
