from PIL import Image, ImageDraw, ImageFont

example_list = [['BORIANDER', 'warning', False], ['biglander', 'dark', False], ['biglander', 'dark', True], ['kojander', 'danger', False], ['nuuuuuuuuuroślaner', 'primary', True], ['zor', 'success', False], ['sdfdssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss', 'warning', True], ['sdfdsssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssdfdsssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssdfdssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss', 'dark', True], ['BORIANDER2', 'dark', False]]
plain = ['static/images/blank.jpg', 160, 106, 'spacing=']
notebook = ['static/images/notebook.jpg', 160, 106, 'spacing=']
retro = ['static/images/retro.png', 160, 106, 'spacing=']
example_font = 'segoesc'

# Render tasks on an image
def create_task_image(list_type, task_list):

    img = Image.open(list_type[0])
    draw = ImageDraw.Draw(img)

    title_font = ImageFont.truetype(f'static/fonts/{example_font}.ttf', 40)
    task_font = ImageFont.truetype(f'static/fonts/{example_font}.ttf', 25)

    title_text = "My To-Do List"
    draw.text((50, 30), title_text, fill="black", font=title_font)

    # Draw each task with different styles
    colors = ["red", "green", "blue", "purple", "orange"]
    y_position = 100  # Initial vertical position for tasks

    for i, task in enumerate(task_list):
        color = colors[i % len(colors)]  # Cycle through colors
        draw.text((50, y_position), f"- {task}", fill=color, font=task_font)
        y_position += 50

    img.save("C:/Users/hp-pc/Downloads/to-do-list.png")
    print(f"Task image saved to: {'C:/Users/hp-pc/Downloads/to-do-list.png'}")

create_task_image(notebook, example_list)
