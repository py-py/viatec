# Make directory
```bash
mkdir viatec
cd viatec
```

# Make virtualenv and activate it
```bash
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```

# Run script in background
```bash
python server.py {eth0} {path} &

```
# Example
```bash
python server.py en0 . 
```
# Help
```bash
python server.py --help

```

