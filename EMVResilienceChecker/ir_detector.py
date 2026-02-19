import os
import re
#from classifier import Classifier
from constants import SHORT_WORDS_THRESHOLD
import nltk
from nltk.corpus import brown
# nltk.download('brown')  
english_words = set(word.lower() for word in brown.words())

def is_renamed(identifier):
    # parts = re.findall(r'[A-Za-z][a-z]*|[A-Z][a-z]*|[0-9]+', identifier)
    parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+', identifier)
    if not parts:
        return False
    english_parts = [p.lower() for p in parts if p.lower() in english_words]
    return _is_mostly_short_words(english_parts) < SHORT_WORDS_THRESHOLD or not _is_mostly_english_words(english_parts, parts)

#def is_renamed_llm(identifier):
#    classifier = Classifier()
#    query = "The provided identifier is from decompiled Android app code. Does it look like it was renamed for obfuscation purposes? Just say yes or no and nothing else."
#    return classifier.classify(identifier, query)

def _is_mostly_english_words(english_parts, parts):
    return len(english_parts) >= max(1, len(parts) // 2)

def _is_mostly_short_words(english_parts):
    if len(english_parts) == 0:
        return SHORT_WORDS_THRESHOLD + 1
    total_length = sum(len(p) for p in english_parts)
    avg_length = total_length / len(english_parts)
    return avg_length 

if __name__ == "__main__":
    import pandas as pd
    import nltk
    from nltk.corpus import brown
    nltk.download('brown')  
    english_words = set(word.lower() for word in brown.words())

    from constants import SHORT_WORDS_THRESHOLD
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


    df = pd.read_excel("./output/identifiers_validation_sample.xlsx", usecols=["Identifier", "final_human_label"]).dropna()

    predicted = []
    human_labels = []

    # Add predicted labels to the DataFrame
    df["Predicted"] = df["Identifier"].apply(is_renamed)
    print(df["Predicted"])

    # Compute metrics
    acc = accuracy_score(df["final_human_label"], df["Predicted"])
    prec = precision_score(df["final_human_label"], df["Predicted"], average='binary')
    rec = recall_score(df["final_human_label"], df["Predicted"], average='binary')
    f1 = f1_score(df["final_human_label"], df["Predicted"], average='binary')

    # Print results
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
   
    diffs = df[df["final_human_label"] != df["Predicted"]]
    print("\nMismatches:")
    print(diffs[["Identifier", "final_human_label", "Predicted"]])

    df.to_excel("./output/identifiers_validation_sample.xlsx", index=False)
