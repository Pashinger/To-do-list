from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from flask import url_for
#
LIST_STYLES = {
    'plain': {
        'path': f'{url_for("static", filename="images/plain.jpg")}',
        'title_x': 520,
        'title_y': 84,
        'text_x': 130,
        'text_y': 204,
        'title_size': 60,
        'text_size': 38,
        'spacing_short': 68,
        'spacing_long': 44,
        'wrap_length': 90,
        'max_body_length': 34.5
    },
    'retro': {
        'path': f'{url_for("static", filename="images/retro.jpg")}',
        'title_x': 470,
        'title_y': 154,
        'text_x': 150,
        'text_y': 254,
        'title_size': 60,
        'text_size': 38,
        'spacing_short': 68,
        'spacing_long': 44,
        'wrap_length': 60,
        'max_body_length': 32.5
    },
    'notebook': {
        'path': f'{url_for("static", filename="images/notebook.jpg")}',
        'title_x': 250,
        'title_y': 84,
        'text_x': 150,
        'text_y': 150,
        'title_size': 40,
        'text_size': 26,
        'spacing_short': 59,
        'spacing_long': 29.5,
        'wrap_length': 35,
        'max_body_length': 31
    }
}

FONT_OFFSETS = {
    'times': {
        'plain_title_x_date': -180,
        'plain_title_x_no_date': -30,
        'retro_title_x_date': -152,
        'retro_title_x_no_date': 0,
        'notebook_title_x_date': 0,
        'notebook_title_x_no_date': 70,
        'text_y': 5,
        'title_y': 0,
        'text_wrapping_lower_plain': 0.35,
        'text_wrapping_lower_retro': 0.09,
        'text_wrapping_lower_notebook': -0.34,
        'text_wrapping_upper_plain': 0.9,
        'text_wrapping_upper_retro': 0.4,
        'text_wrapping_upper_notebook': -0.26
    },
    'cour': {
        'plain_title_x_date': -306,
        'plain_title_x_no_date': -100,
        'retro_title_x_date': -306,
        'retro_title_x_no_date': -100,
        'notebook_title_x_date': -96,
        'notebook_title_x_no_date': 40,
        'text_y': 8,
        'title_y': 0,
        'text_wrapping_lower_plain': 1.14,
        'text_wrapping_lower_retro': 0.69,
        'text_wrapping_lower_notebook': 0.085,
        'text_wrapping_upper_plain': 0.6,
        'text_wrapping_upper_retro': 0.22,
        'text_wrapping_upper_notebook': -0.4
    },
    'segoesc': {
        'plain_title_x_date': -306,
        'plain_title_x_no_date': -75,
        'retro_title_x_date': -290,
        'retro_title_x_no_date': -83,
        'notebook_title_x_date': -84,
        'notebook_title_x_no_date': 45,
        'text_y': 0,
        'title_y': -8,
        'text_wrapping_lower_plain': 0.5,
        'text_wrapping_lower_retro': 0.18,
        'text_wrapping_lower_notebook': -0.24,
        'text_wrapping_upper_plain': 1.5,
        'text_wrapping_upper_retro': 0.9,
        'text_wrapping_upper_notebook': 0
    }
}


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


def calculate_body_length(
        chosen_style: str,
        list_font: str,
        tasks_list: list[tuple[str, str, bool]],
        chosen_title: str
) -> bool:
    """Check if the tasks will fit the image by calculating their relative length.

    Args:
        chosen_style (str): The style of the image ('plain', 'notebook' or 'retro').
        list_font (str): The font file name (without extension) for the text.
        tasks_list (list[tuple[str, str]]): A list of tasks where each task is
                                            a tuple (text, color).
        chosen_title (str): The title to be displayed on the image.

    Returns:
        bool: True if all tasks can be accommodated within the downloaded to-do list;
              otherwise, returns False if the number of tasks exceeds the available space.
    """
    body_length = 0
    tasks_wrapped = []
    list_style = LIST_STYLES[chosen_style]

    if len(tasks_list) > 0:
        if chosen_title:
            if chosen_style == 'notebook':
                body_length += 2
            else:
                body_length += 2.5

        for item in tasks_list:
            text = item[0]
            line_length = 0
            wrapped_item = []
            current_line = ''

            # Count the number of occupied lines on a page, wrapping included
            for char in text:
                if char.isupper():
                    line_length += (1.45 + FONT_OFFSETS[list_font][f'text_wrapping_upper_{chosen_style}'])
                else:
                    line_length += (1 + FONT_OFFSETS[list_font][f'text_wrapping_lower_{chosen_style}'])
                if line_length >= list_style['wrap_length']:
                    if current_line[-1] == ' ':
                        wrapped_item.append(current_line)
                        current_line = char
                    else:
                        wrapped_item.append(current_line + '-')
                        current_line = char
                    line_length = 0
                    body_length += 1
                else:
                    current_line += char
            wrapped_item.append(current_line)
            tasks_wrapped.append(wrapped_item)
            body_length += 2

    if body_length > list_style['max_body_length']:
        return False
    else:
        return True


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
    list_style = LIST_STYLES[chosen_style]
    tasks_wrapped = []
    corresponding_colors = []
    y_position = list_style['text_y'] + FONT_OFFSETS[list_font]['text_y']

    # Prepare the canvas and fonts
    img = Image.open(list_style['path'])
    draw = ImageDraw.Draw(img)
    title_font = ImageFont.truetype(f'{url_for("static", filename=f"fonts/{list_font}.ttf")}', list_style['title_size'])
    task_font = ImageFont.truetype(f'{url_for("static", filename=f"fonts/{list_font}.ttf")}', list_style['text_size'])

    # Draw the title
    if chosen_title:
        if len(chosen_title) > 13:
            title_offset = FONT_OFFSETS[list_font][f'{chosen_style}_title_x_date']
        else:
            title_offset = FONT_OFFSETS[list_font][f'{chosen_style}_title_x_no_date']
        draw.text((list_style['title_x'] + title_offset,
                   list_style['title_y'] + FONT_OFFSETS[list_font]['title_y']),
                  chosen_title,
                  fill='black', font=title_font)
    else:
        y_position = list_style['title_y'] + FONT_OFFSETS[list_font]['text_y'] + 5

    # Handle wrapping of tasks' text and their color conversion
    for item in tasks_list:
        color = item[1]
        corresponding_colors.append(color)
        text = item[0]
        line_length = 0
        wrapped_item = []
        current_line = ''

        # Reformat the task text so that words which wrap are cut into separate list elements
        for char in text:
            if char.isupper():
                line_length += (1.45 + FONT_OFFSETS[list_font][f'text_wrapping_upper_{chosen_style}'])
            else:
                line_length += (1 + FONT_OFFSETS[list_font][f'text_wrapping_lower_{chosen_style}'])
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
