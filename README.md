
<img src="chihuahua-logo.png" alt="drawing" width="100"/>

# Chihuahua

A very small guard dog ... and a minimalist authentication server designed to work with [Traefik forward auth](https://doc.traefik.io/traefik/v2.0/middlewares/forwardauth/)

## Development

**Requires**:

- python >= 3.11
- docker and docker-compose

**Setup**

1. Install the python requirements in a virtual environment:

```cmd

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements_dev.txt

# with Conda
conda create -n cn-auth python=3.8
conda activate cn-auth
pip install -r requirements.txt -r requirements_dev.txt
```

2. In different terminal windows:

   a. Start Traefik and dummy services for development:

   ```
   docker-compose -f docker-compose.dev.yml up
   ```

   b. Start the Chihuahua server:

   ```cmd
   export $(xargs < .env.dev)
   uvicorn chihuahua.main:app --reload --port 8000
   ```

The API's documentation is available at `http://localhost/auth/api/docs`

### Run testsuite

For the tests to run successfully, Traefik, the dummy services, and the Chihuahua server must be running as described above.

```cmd
pytest tests/
```
