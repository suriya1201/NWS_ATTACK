from flask import Flask, redirect, request

app = Flask(__name__)

redirect_ip = "192.168.1.19"  # Replace with your IP address

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def redirect_to_port(path):
    return redirect(f"http://{redirect_ip}:8080/{path}", code=302)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
