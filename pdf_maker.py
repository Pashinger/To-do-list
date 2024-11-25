from PIL import Image, ImageDraw, ImageFont

# example_list = [['e', 'warning', False], ['s                sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss', 'dark', False], ['na siwta sobie posprzątamy i bedzie bardzo milo a potem bedziemy mialac i goladac paddingtona i krol', 'secondary', False], ['NA SIWTA SOBIE POSPRZĄTAMY I BEDZIE BARDZO MILO A POTEM BEDZIEMY MIALAC I GOLADAC PADDINGTONA I KROL', 'primary', False], ['nuroślaner', 'secondary', False], ['BORIANDER', 'warning', False], ['BORIANDER', 'warning', False], ['biglander', 'primary', False], ['kojander', 'danger', False], ['zor', 'success', False], ['BORIANDER2', 'dark', False]]


def convert_colors(list_to_convert):
    converted_list = []
    for color in list_to_convert:
        if color == 'success':
            color = 'green'
        elif color == 'warning':
            color = 'yellow'
        elif color == 'primary':
            color = 'blue'
        elif color == 'danger':
            color = 'red'
        elif color == 'secondary':
            color = 'gray'
        elif color == 'dark':
            color = 'black'
        converted_list.append(color)
    return converted_list


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


# Render tasks on an image
def create_task_image(chosen_style, list_font, tasks_list):
    list_style = list_styles[chosen_style]
    tasks_wrapped = []
    corresponding_colors = []
    y_position = list_style['text_y']
    img = Image.open(list_style['path'])
    draw = ImageDraw.Draw(img)

    title_font = ImageFont.truetype(f'static/fonts/{list_font}.ttf', 40)
    task_font = ImageFont.truetype(f'static/fonts/{list_font}.ttf', 26)

    title_text = 'My To-Do List'
    draw.text((list_style['title_x'], list_style['title_y']), title_text, fill='black', font=title_font)

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

    # tu będzie return robiony i będzie można ściągnąc obrazek w templacie lub wysłać na maila
    img.save("C:/Users/hp-pc/Downloads/to-do-list.png")