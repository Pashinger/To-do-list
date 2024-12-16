from requests import get

URL = 'https://zenquotes.io/api/quotes/'


def get_quote() -> tuple[str, str | bool]:
    """Fetch a random quote and its author from the ZenQuotes API.

    Returns:
        tuple[str, str | bool]: A tuple containing the quote and the author. If the API
                                request is successful, both the quote and the author are returned as strings.
                                If the API service is unavailable, a default message is returned as the quote,
                                and the author is set to False.
    """
    response = get(url=URL)
    data = response.json()[0]
    quote = data['q']
    author = data['a']
    if quote == 'Unrecognized API request. Visit zenquotes.io for documentation.':
        quote = 'Service currently unavailable. Try again later!'
        author = False
    return quote, author
