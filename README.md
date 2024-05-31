# Bandwidth Sharing

This is the code for *Bandwidth Sharing*.

+ [Project Page](https://chasesecurity.github.io/bandwidth_sharing/)
+ [Paper](https://arxiv.org/abs/2404.10610)

## Overview

Emerging in recent years, residential proxies (RESIPs) feature multiple unique characteristics when compared with traditional network proxies (e.g., commercial VPNs), particularly, the deployment in residential networks rather than data center networks, the worldwide distribution in tens of thousands of cities and ISPs, and the large scale of millions of exit nodes. All these factors allow RESIP users to effectively masquerade their traffic flows as ones from authentic residential users, which leads to the increasing adoption of RESIP services, especially in malicious online activities. 

Multiple novel tools have been designed and implemented in this study, which include a general framework to deploy RESIP nodes and collect RESIP traffic in a distributed manner, a RESIP traffic analyzer to efficiently process RESIP traffic logs and surface out suspicious traffic flows, and multiple machine learning based RESIP traffic classifiers to timely and accurately detect whether a given traffic flow is RESIP traffic or not. This repo will release some source code.

As the results, we have collected and will release the largest-ever and realistic RESIP traffic dataset, which is of 3TB in size, consists of over 116 million traffic flows, and involves traffic destinations of 188K unique IP addresses. Also, leveraging the RESIP traffic analyzer, multiple novel security findings have been distilled regarding the malicious usage of RESIPs, e.g., relaying large-scale email spam activities targeting millions of recipients, and the masquerade of miscreants as local residents when suspiciously visiting sensitive websites operated by critical organizations, e.g., governments,  military agencies, and companies operating critical infrastructures. Lastly, our machine learning based RESIP traffic classifiers turn out to be both effective and efficient. Particularly, when classifying whether a traffic flow is relayed by RESIPs or not, our transformer-based classifier has achieved a recall of 93.04\% and a precision of 92.87\%, by only ingesting the first 5 packets of each given traffic flow.

## Datasets Release

To avoid misuse by miscreants, the dataset will be provided upon request and background checking. To apply for the access, please contact the corresponding author [Xianghang Mi](mailto:xianghangmi@gmail.com). You can also directly fill [this Google form](https://forms.gle/EvjjXMGrVTub2V1G7), and we will contact you asap.

## Code Release

You may need to read the `README.md` for dependencies and usage under the specific folder.

The RESIP traffic analysis code is at [traffic_analysis_scripts](./traffic_analysis_scripts/).

The RESIP node collector code is at [infiltration_scripts](./infiltration_scripts).

The RESIP traffic collector code is at [traffic_capture_scripts](./traffic_capture_scripts).

The RESIP traffic classifier code is at [traffic_classifier_scripts](./traffic_classifier_scripts).

<!-- You can get resulting model from [our Hugging Face repo](https://huggingface.co/). -->

## Bibtex

```
@article{wang2024port,
      title={Bandwidth Sharing}, 
      author={Ronghong Huang, Dongfang Zhao, Xianghang Mi, Xiaofeng Wang},
      year={2024},
      eprint={2404.10610},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}
```
