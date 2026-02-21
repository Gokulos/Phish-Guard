import pandas as pd

def merged_data():
    #Dataset from - Phishtank
    phish = pd.read_csv(r"D:\Study\Projects\Phishing URL Detection\verified_online.csv")
    # Keeping only verified and online phishing
    phish = phish[(phish["verified"] == "yes") & (phish["online"] == "yes")]
    phish = phish[["url"]].drop_duplicates().reset_index(drop=True)
    phish["label"] = 1

    print(phish.shape)
    print(phish.head())

    #This List Does not mean it is phishing free, its just ranked better!!!
    Top_Websites= pd.read_csv(r"D:\Study\Projects\Phishing URL Detection\top-1mi.csv", header=None) #Dataset from - Cisco Umbrella (Formerly Alexa) 
    websites = Top_Websites.iloc[:, 1].tolist()
    legit = pd.DataFrame(websites, columns=["url"])
    legit = legit[["url"]].drop_duplicates().reset_index(drop=True)
    legit["label"] = 0
    print(legit.shape)
    ##print(legit.head())

    # To reduce the model Bias, Reducing the no of non phising websites to make it similar count to phishing
    # Therefore Randomly sampled exactly 56,421 rows
    legit_new = legit.sample(n=56421, random_state=42) 

    # Verify the shape
    print(legit_new.shape) 
    print(legit_new.head())

    #Merging both legitimate(Only Top ranked Not exactly Legitimate) and phishing urls(Known)
    df = pd.concat([phish, legit_new]).sample(frac=1).reset_index(drop=True)
    print(df.shape)
    print(df.head())
    return df

if __name__ == "__main__":
    data = merged_data()
