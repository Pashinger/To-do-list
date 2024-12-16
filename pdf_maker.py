from PIL import Image, ImageDraw, ImageFont
from io import BytesIO


def convert_colors(list_to_convert: list[str]) -> list[str]:
    """Convert Bootstrap color names to their corresponding standard color names.

    Args:
        list_to_convert (list[str]): A list of color names in Bootstrap style.

    Returns:
        list[str]: A list of corresponding standard color names.
    """
    color_map = {
        'success': 'green',
        'warning': 'yellow',
        'primary': 'blue',
        'danger': 'red',
        'secondary': 'gray',
        'dark': 'black'
    }
    return [color_map[f'{color}'] for color in list_to_convert]


list_styles = {
    'plain': {
        'path': 'static/images/plain.jpg',
        'title_x': 520,
        'title_y': 116,
        'text_x': 130,
        'text_y': 200,
        'spacing_short': 59,
        'spacing_long': 29.5,
        'wrap_length': 90
    },
    'notebook': {
        'path': 'static/images/notebook.jpg',
        'title_x': 250,
        'title_y': 76,
        'text_x': 150,
        'text_y': 150,
        'spacing_short': 59,
        'spacing_long': 29.5,
        'wrap_length': 35
    },
    'retro': {
        'path': 'static/images/retro.jpg',
        'title_x': 470,
        'title_y': 116,
        'text_x': 150,
        'text_y': 190,
        'spacing_short': 59,
        'spacing_long': 29.5,
        'wrap_length': 60
    }
}


def create_task_image(
        chosen_format: str,
        chosen_style: str,
        list_font: str,
        tasks_list: list[tuple[str, str, bool]],
        chosen_title: str
) -> BytesIO:
    """Render a to-do list on an image and return the image as a stream.

    Args:
        chosen_format (str): The image format (e.g., 'jpg', 'png').
        chosen_style (str): The style of the image (e.g., 'plain', 'notebook', 'retro').
        list_font (str): The font file name (without extension) for the text.
        tasks_list (list[tuple[str, str]]): A list of tasks where each task is
                                            a tuple (text, color).
        chosen_title (str): The title to be displayed on the image.

    Returns:
        BytesIO: The generated image as a binary stream.
    """
    if chosen_format == 'jpg':
        chosen_format = 'jpeg'
    list_style = list_styles[chosen_style]
    tasks_wrapped = []
    corresponding_colors = []
    y_position = list_style['text_y']

    # Prepare the canvas and fonts
    img = Image.open(list_style['path'])
    draw = ImageDraw.Draw(img)
    title_font = ImageFont.truetype(f'static/fonts/{list_font}.ttf', 40)
    task_font = ImageFont.truetype(f'static/fonts/{list_font}.ttf', 26)

    # Draw the title
    draw.text((list_style['title_x'], list_style['title_y']), chosen_title, fill='black', font=title_font)

    # Handle wrapping of tasks' text and their color conversion
    for item in tasks_list:
        color = item[1]
        corresponding_colors.append(color)
        text = item[0]
        line_length = 0
        wrapped_item = []
        current_line = ''

        for char in text:
            if char.isupper():
                line_length += 1.45
            else:
                line_length += 1
            if line_length >= list_style['wrap_length']:
                if current_line[-1] == ' ':
                    wrapped_item.append(current_line)
                    current_line = char
                else:
                    wrapped_item.append(current_line + '-')
                    current_line = char
                line_length = 0
            else:
                current_line += char
        wrapped_item.append(current_line)
        tasks_wrapped.append(wrapped_item)

    # Draw tasks
    color_index = 0
    converted_corresponding_colors = convert_colors(corresponding_colors)
    for line in tasks_wrapped:
        color = converted_corresponding_colors[color_index]
        for task in line:
            if tasks_wrapped[0] == task:
                draw.text((list_style['text_x'], y_position), f'- {task}', fill=color, font=task_font)
                y_position += list_style['spacing_long']
            else:
                draw.text((list_style['text_x'] + 17, y_position), f'{task}', fill=color, font=task_font)
                y_position += list_style['spacing_long']
        y_position += list_style['spacing_long']
        color_index += 1

    # Save the image to a stream
    image_stream = BytesIO()
    img.save(image_stream, chosen_format.upper())
    image_stream.seek(0)
    return image_stream
