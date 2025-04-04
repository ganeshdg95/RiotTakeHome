# Riot take-home exercise

HTTP API with 4 endpoints that handle JSON payloads for encryption, decryption, signing, and verification operations.

I used uv to manage dependencies and Django-ninja to build the API.

# Setting up virtual environment and app

After clonning the repository, navigate to the root folder. Where the `pyproject.toml` and `uv.lock` files should be located.

Create a virtual environment and install the required dependencies using [uv](https://docs.astral.sh/uv/).

```sh
pip install uv
uv venv
uv sync
```

After setting up the virtual environment, you can run any commands with the environment created by uv by prepending `uv run` to your command. For example,

```sh
uv run riot/manage.py runserver
```

Before running the server for the first time, you will have to run migrations,

```sh
uv run riot/manage.py migrate
```

# Structure of the project

The project has the following structure. This is a generic structure generated by Django.

```plaintext
Root_folder/│
│── .venv/                      # Virtual environment
│── uv.lock/                    # Lists required packages with specific version
│── pyproject.toml              # Project description, version and dependencies
│── riot/                       # Main app folder
|───|── manage.py               # Django management script
│───│── riot/                   # Main app containing settings file and other generic files generated by django
│───│───│── secure_api/         # App containing the API. Depends on settings from main app.
│───│───│───|── api.py          # Defines the API.
│───│───│───|── test.py         # Defines a test suite for the API.
│───│───│───|── algorithms.py   # Defines encryption, and authentication algorithms used by the API.
│───│───│───|── schema.py       # Defines input and output schemas used by the API.
```

The important files to look at are `secure_api/api.py`, `secure_api/schema.py`, `secure_api/algorithms.py` and `secure_api/test.py`.

# Testing and visualizing

The API can be tested by running a test suite that checks for the requirements of the exercise. You can run the test suite with,

```sh
uv run riot/manage.py test riot.secure_api
```

Reading the tests is a great way to understand the code.

You can also use the swagger to test each api method manually. To do this, run,

```sh
uv run riot/manage.py runserver
```

and then go to `http://127.0.0.1:8000/api/docs`. You can also read the documentation of each method in the swagger.

