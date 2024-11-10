# ollama_lib.py

import json
import requests

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url.rstrip('/')

    def chat(self, model, messages, tools=None):
        """
        Führt einen Chat-Aufruf mit Tool-Unterstützung durch.
        
        :param model: Der zu verwendende Modellname.
        :param messages: Nachrichten für das Gespräch im Chat.
        :param tools: Eine Liste von Tools für die Tool-Calls.
        :return: Die Antwort der API.
        """
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages
        }
        
        if tools:
            payload["tools"] = tools

        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=json.dumps(payload), headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Fehler bei der LLM-Anfrage: {response.status_code} - {response.text}")
