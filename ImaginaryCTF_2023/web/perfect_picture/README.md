# Perfect Picture

## Description

> Someone seems awful particular about where their pixels go...
>
> Author: FIREPONY57
>
> https://imaginaryctf.org/r/Gdmod#perfect_picture.zip \
> http://perfect-picture.chal.imaginaryctf.org

Tags: _web_

## Solution

We are provided with the source code, the most important thing to take into account is the function `check()`

```python
def check(uploaded_image):
    with open('flag.txt', 'r') as f:
        flag = f.read()
    with Image.open(app.config['UPLOAD_FOLDER'] + uploaded_image) as image:
        w, h = image.size
        if w != 690 or h != 420:
            return 0
        if image.getpixel((412, 309)) != (52, 146, 235, 123):
            return 0
        if image.getpixel((12, 209)) != (42, 16, 125, 231):
            return 0
        if image.getpixel((264, 143)) != (122, 136, 25, 213):
            return 0

    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(app.config['UPLOAD_FOLDER'] + uploaded_image)[0]
        try:
            if metadata["PNG:Description"] != "jctf{not_the_flag}":
                return 0
            if metadata["PNG:Title"] != "kool_pic":
                return 0
            if metadata["PNG:Author"] != "anon":
                return 0
        except:
            return 0
    return flag
```

This function will give us the flag if the image we upload meets the following criteria:

1. The image has a width of 690 pixels and a height of 420 pixels.
2. The color values of the following specific pixels in the image matches the rgb criteria.
   - Pixel at (412, 309) should have the color (52, 146, 235, 123).
   - Pixel at (12, 209) should have the color (42, 16, 125, 231).
   - Pixel at (264, 143) should have the color (122, 136, 25, 213).
3. The following metadata is set in the image with the specific values:
   - Description: jctf{not_the_flag}
   - Title: kool_pic
   - Author: anon

To create such an image, you can use any image editing software that allows you to specify the dimensions and pixel values manually. Otherwise, you can use `Python` and the `Pillow` library as I did.

```python
from PIL import Image

# Create a new image with the desired dimensions (690x420) and a transparent background
image = Image.new("RGBA", (690, 420), (0, 0, 0, 0))

# Set the pixel values for the specific pixels
image.putpixel((412, 309), (52, 146, 235, 123))
image.putpixel((12, 209), (42, 16, 125, 231))
image.putpixel((264, 143), (122, 136, 25, 213))

# Save the image to a file
image.save("perfect_picture.png")

# Close the image
image.close()
```

To set the metadata properties, I used a tool called `exiftool` to add the specific metadata to the image.

```shell
exiftool -PNG:Description="jctf{not_the_flag}" -PNG:Title="kool_pic" -PNG:Author="anon" perfect_picture.png
```

Finally, I uploaded the image and got the flag!

Flag `ictf{7ruly_th3_n3x7_p1c4ss0_753433}`
