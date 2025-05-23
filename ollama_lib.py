import json
import requests

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url.rstrip('/')

    def chat(self, model, messages, tools=None):
        """
        Executes a chat call with tool support.

        :param model: The model name to use.
        :param messages: Messages for the conversation in the chat.
        :param tools: A list of tools for tool calls.
        :return: The API response.
        """
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages
        }

        if tools:
            payload["tools"] = tools

        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error in LLM request: {e}")

    def generate(self, model="llama2", prompt="Say hello"):
        """Generates text from a prompt."""
        url = f"{self.base_url}/v1/generate"
        payload = {
            "model": model,
            "prompt": prompt,
        }
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
            response.raise_for_status()
            return response.json().get("response") #get the response from the JSON
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error in LLM request: {e}")