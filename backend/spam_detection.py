import pickle
import string
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from nltk.tokenize import RegexpTokenizer

# Load once
tokenizer = RegexpTokenizer(r'\w+')
ps = PorterStemmer()

def transform_text(text):
    text = text.lower()
    text = tokenizer.tokenize(text)

    y = []
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(ps.stem(i))

    return " ".join(y)

# Load model and vectorizer
tfidf = pickle.load(open('model_files/vectorizer.pkl','rb'))
model = pickle.load(open('model_files/model.pkl','rb'))
def predict_spam(text):
    transformed_sms = transform_text(text)
    vector_input = tfidf.transform([transformed_sms])
    result = model.predict(vector_input)[0]
    return "Spam" if result == 1 else "Not Spam"

# Test
#print(predict_spam("hi how are you!"))
