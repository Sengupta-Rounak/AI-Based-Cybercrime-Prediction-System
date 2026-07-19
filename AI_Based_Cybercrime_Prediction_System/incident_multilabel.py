from __future__ import annotations
import csv,gzip,json,math,re
from collections import Counter
from pathlib import Path
from typing import Any
TOKEN_RE=re.compile(r"[a-z][a-z0-9_-]{1,}")
URL_RE=re.compile(r"https?://\S+|www\.\S+",re.I);EMAIL_RE=re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b",re.I);NUMBER_RE=re.compile(r"\b\d+(?:\.\d+)?\b");NON_ALNUM_RE=re.compile(r"[^a-z0-9_ ]+");SPACE_RE=re.compile(r"\s+")
STOPWORDS={"the","a","an","and","or","to","of","in","on","for","with","from","by","at","as","is","was","were","be","been","being","that","this","it","its","their","they","them","after","before","through","into","no","not","could","would","should","had","has","have","within","without","while","when","which","who","during","than","then","also"}
ACTIONS={"PHISHING":"Quarantine the message, block linked infrastructure, reset exposed credentials and notify affected users.","RANSOMWARE":"Isolate affected systems, protect offline backups and activate the ransomware response plan.","MALWARE":"Isolate the endpoint, block indicators and perform forensic triage.","ACCOUNT_TAKEOVER":"Terminate sessions, reset credentials, restore MFA and review account changes.","WEB_EXPLOITATION":"Block the request pattern, review application controls and inspect server logs.","SOCIAL_ENGINEERING":"Verify the request through a trusted channel and protect exposed identities or credentials.","PRIVILEGE_MISUSE":"Restrict the account, preserve audit evidence and review privileged actions.","DATA_BREACH":"Contain access, preserve evidence, assess exposed data and initiate notification procedures.","BOTNET_C2":"Isolate suspected devices and block command-and-control infrastructure.","DOS_DDOS":"Apply rate limiting and upstream filtering while protecting service availability.","BRUTE_FORCE":"Rate-limit authentication, protect targeted accounts and require strong MFA.","PORT_SCAN":"Review the source and targeted services and restrict unnecessary exposure.","SQL_INJECTION":"Block the request, review parameterised queries and inspect database access.","XSS":"Block the payload and apply output encoding and content-security controls."}
SEVERITY={"PHISHING":"High","RANSOMWARE":"Critical","MALWARE":"High","ACCOUNT_TAKEOVER":"Critical","WEB_EXPLOITATION":"High","SOCIAL_ENGINEERING":"High","PRIVILEGE_MISUSE":"High","DATA_BREACH":"Critical","BOTNET_C2":"High","DOS_DDOS":"Critical","BRUTE_FORCE":"High","PORT_SCAN":"Medium","SQL_INJECTION":"Critical","XSS":"High"}
def token_features(text:str):
    n=URL_RE.sub(" URLTOKEN ",str(text).lower());n=EMAIL_RE.sub(" EMAILTOKEN ",n);n=NUMBER_RE.sub(" NUMTOKEN ",n);n=NON_ALNUM_RE.sub(" ",n);n=SPACE_RE.sub(" ",n).strip();tokens=[t for t in TOKEN_RE.findall(n) if len(t)>1 and t not in STOPWORDS];f=[f"u:{t}" for t in tokens];f.extend(f"b:{a}_{b}" for a,b in zip(tokens,tokens[1:]));compact="_".join(tokens)[:5000]
    for size in (3,4,5):
        limit=max(len(compact)-size+1,0);step=max(1,math.ceil(limit/1000)) if limit else 1
        for i in range(0,limit,step):
            gram=compact[i:i+size]
            if "__" not in gram and gram.strip("_"):f.append(f"c{size}:{gram}")
    return f
def sigmoid(x):
    if x>=0:z=math.exp(-min(x,700));return 1/(1+z)
    z=math.exp(max(x,-700));return z/(1+z)
class PortableIncidentMultiLabelClassifier:
    def __init__(self,model:dict[str,Any]):
        self.model=model;self.labels=list(model["labels"]);self.primary_labels=list(model["primary_labels"]);self.experimental_labels=list(model["experimental_labels"]);self.vocabulary={str(k):int(v) for k,v in model["vocabulary"].items()};self.idf=[float(x) for x in model["idf"]];self.coefficients=[[float(x) for x in row] for row in model["coefficients"]];self.intercepts=[float(x) for x in model["intercepts"]];self.calibration=model["calibration"];self.thresholds={str(k):float(v) for k,v in model["thresholds"].items()};self.readiness=model.get("readiness",{});self.ood=float(model.get("ood_coverage_threshold",0.035))
    @classmethod
    def load(cls,path:Path):
        with gzip.open(path,"rt",encoding="utf-8") as f:return cls(json.load(f))
    def _vector(self,text):
        counts=Counter(token_features(text));known={self.vocabulary[t]:c for t,c in counts.items() if t in self.vocabulary};total=sum(counts.values());coverage=sum(known.values())/max(total,1);values={i:(1+math.log(c))*self.idf[i] for i,c in known.items()};norm=math.sqrt(sum(v*v for v in values.values())) or 1.0;return {i:v/norm for i,v in values.items()},coverage,counts
    def predict(self,text:str,evidence_limit:int=10):
        text=str(text or "").strip()
        if len(text)<20:raise ValueError("Enter a longer incident narrative before classification.")
        vector,coverage,counts=self._vector(text);probs=[]
        for j,label in enumerate(self.labels):
            score=self.intercepts[j]+sum(self.coefficients[j][i]*v for i,v in vector.items());cal=self.calibration[j];prob=sigmoid(float(cal.get("slope",1))*score+float(cal.get("intercept",0)));probs.append((label,prob))
        ordered=sorted(probs,key=lambda x:x[1],reverse=True);selected=[]
        for label,prob in ordered:
            threshold=self.thresholds[label]
            if prob>=threshold:selected.append({"label":label,"display_label":label.replace("_"," ").title(),"probability":prob,"threshold":threshold,"readiness":self.readiness.get(label,{}).get("readiness","Unknown")})
        out_of_scope=coverage<self.ood;decision="REVIEW" if out_of_scope or not selected else "THREAT_DETECTED";top=ordered[0][0];top_prob=ordered[0][1];evidence=[]
        top_index=self.labels.index(top)
        for token,count in counts.items():
            if not token.startswith(("u:","b:")):continue
            idx=self.vocabulary.get(token)
            if idx is None:continue
            contribution=self.coefficients[top_index][idx]*((1+math.log(count))*self.idf[idx])
            if contribution>0:evidence.append({"term":token.split(":",1)[-1].replace("_"," "),"contribution":contribution,"count":count})
        evidence.sort(key=lambda x:x["contribution"],reverse=True)
        return {"predicted_attack":top if selected else "UNCLASSIFIED_INCIDENT","display_attack":top.replace("_"," ").title() if selected else "Incident Requires Review","predicted_labels":selected,"confidence":top_prob,"decision":decision,"binary_label":"MALICIOUS_INCIDENT","lexical_coverage":coverage,"out_of_scope":out_of_scope,"severity":SEVERITY.get(top,"Medium"),"recommended_action":ACTIONS.get(top,"Escalate the incident for analyst review."),"probabilities":[{"label":l,"probability":p,"threshold":self.thresholds[l],"readiness":self.readiness.get(l,{}).get("readiness","Unknown")} for l,p in ordered],"evidence":evidence[:evidence_limit],"model_note":self.model.get("scientific_note","")}
def multilabel_metrics(actual,predicted,labels):
    result={};tp_all=fp_all=fn_all=0;f_values=[]
    for label in labels:
        tp=sum(label in a and label in p for a,p in zip(actual,predicted));fp=sum(label not in a and label in p for a,p in zip(actual,predicted));fn=sum(label in a and label not in p for a,p in zip(actual,predicted));precision=tp/(tp+fp) if tp+fp else 0.0;recall=tp/(tp+fn) if tp+fn else 0.0;f1=2*precision*recall/(precision+recall) if precision+recall else 0.0;support=sum(label in a for a in actual);result[label]={"precision":precision,"recall":recall,"f1":f1,"support":support};tp_all+=tp;fp_all+=fp;fn_all+=fn;f_values.append(f1)
    micro_p=tp_all/(tp_all+fp_all) if tp_all+fp_all else 0;micro_r=tp_all/(tp_all+fn_all) if tp_all+fn_all else 0;micro_f1=2*micro_p*micro_r/(micro_p+micro_r) if micro_p+micro_r else 0;exact=sum(a==p for a,p in zip(actual,predicted))/max(len(actual),1);hamming=sum(len(a.symmetric_difference(p)) for a,p in zip(actual,predicted))/(max(len(actual),1)*max(len(labels),1));return {"records":len(actual),"micro_precision":micro_p,"micro_recall":micro_r,"micro_f1":micro_f1,"macro_f1":sum(f_values)/max(len(f_values),1),"exact_match_accuracy":exact,"hamming_loss":hamming,"per_label":result}
def evaluate_csv(classifier,path:Path):
    actual=[];predicted=[]
    with path.open(encoding="utf-8-sig",newline="") as f:
        rows=list(csv.DictReader(f))
    if not rows:raise ValueError("The evaluation CSV contains no records.")
    text_col=next((c for c in rows[0] if c.strip().lower() in {"summary","incident_text","description","narrative","text"}),None)
    if not text_col:raise ValueError("No supported narrative column was detected.")
    for row in rows:
        labels={label for label in classifier.labels if str(row.get("label_"+label,"")).strip().lower() in {"1","true"}}
        if not labels and row.get("labels"):labels={x.strip().upper() for x in str(row["labels"]).split("|") if x.strip().upper() in classifier.labels}
        if not labels:continue
        result=classifier.predict(row[text_col]);actual.append(labels);predicted.append({x["label"] for x in result["predicted_labels"]})
    return multilabel_metrics(actual,predicted,classifier.primary_labels)
