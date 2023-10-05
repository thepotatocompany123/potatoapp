# Initialize a dictionary to store chat history for each session ID
chat_history_dict = {}

# Hardcoded session ID for testing purposes
session_id = 'test123'

# Define a basic conversation
basic_conversation = [
    {"user": "You", "message": "Hello, Bob!"},
    {"user": "Bob", "message": "Hi there! How can I assist you today?"},
    {"user": "You", "message": "I have a question about your services."},
    {"user": "Bob", "message": "Hey, feel free to ask me anything!"},
    {"user": "You", "message": "whatsupp"},
    {"user": "Bob", "message": "Sure, I'm here to help. What's your question?"}
]

# Store the basic conversation in the chat history dictionary
chat_history_dict[session_id] = basic_conversation

# Standard responses for Bob
standard_responses = [
    "Hi there, how can I help you?",
    "Hello! What's on your mind?",
    "Hey, feel free to ask me anything!",
    "Hi, I'm Bob. Let's chat!",
    "Hello, how's your day going?",
    "Greetings! I'm here to assist you.",
    "Howdy! What can I do for you today?",
    "Good day! Ask me anything about potatoes.",
    "Hi, it's Bob. Ready to talk potatoes!",
    "Hello, potato enthusiast! What's your question?"
]

# Define a list of commonly asked questions and answers
common_questions_and_answers = [
    {"question": "What are the different types of potatoes?", "answer": "There are various types of potatoes, "
                                                                        "including russet, red, gold, and fingerling "
                                                                        "potatoes."},
    {"question": "How should I store potatoes?", "answer": "Potatoes should be stored in a cool, dark place with good "
                                                           "ventilation to prevent sprouting and spoilage."},
    {"question": "What are the health benefits of potatoes?", "answer": "Potatoes are a good source of vitamins, "
                                                                        "minerals, and fiber. They provide essential "
                                                                        "nutrients and can be part of a healthy diet."},
    {"question": "How do I prepare mashed potatoes?", "answer": "To make mashed potatoes, boil peeled potatoes until "
                                                                "tender, mash them, and mix with butter, milk, salt, "
                                                                "and pepper."},
    {"question": "What dishes can I make with potatoes?", "answer": "You can make a variety of dishes with potatoes, "
                                                                    "including french fries, potato salad, "
                                                                    "potato soup, and more."},
]