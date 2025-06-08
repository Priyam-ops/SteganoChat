from stegano import lsb

def hide_message(input_image_path: str, message: str, output_image_path: str) -> None:
    """
    Hides a message inside an image and saves the output image.
    """
    secret = lsb.hide(input_image_path, message)
    secret.save(output_image_path)

def reveal_message(image_path: str) -> str:
    """
    Reveals a hidden message from an image.
    """
    return lsb.reveal(image_path)
