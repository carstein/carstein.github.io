---
layout: post
title: "Doing technical interviews"
date: 2021-06-28
---

# Doing technical interviews 

Initial idea behind this *blog* was to post only technical content. This steamed from my distrust for people who only post *opinion* pieces not accompanied by any technical content to assert their knowledge or experience. Admittedly, I was such a person a long time ago and the less I knew the stronger opinions I was posting. Realizing that I've promised myself to focus on technical content because at least it has certain intellectual honesty.

Time has passed and I've started believing that after all, I might have more experience now that would actually entitle me to have opinions about various topics. Twitter, my social platform of choice, does not encourage or even plainly support publishing long form and does not encourage more nuanced discussions. All of this brings us to this article - a first opinion piece on this blog. 

Recently a friend of mine interviewed for a position in an unnamed company. I'm not going to convey his whole experience here but the core of his story was a set of absolutely unprofessional yet terribly common *clichés* that one encounters while doing a technical interview. Because of that I've decided to write a few paragraphs about how I imagine a good interviewing experience should look like. 

Before we begin I need to mention a few important caveats. Through my career I've interviewed probably around hundred people - mostly for security related positions. That means that while not being the most prolific interviewer I've seen enough to form my own conclusions about the whole process. I've been mostly interviewing people for various security positions therefore everything you read here centers on that topic but most of the advice should be directly or indirectly translatable to software engineering roles.

## Goal

We are going to start with the most obvious yet usually forgotten point - why we are even interviewing a given candidate. You would be surprised how many people fail to properly answer these questions. If you are doing this to feel smarter, to floor the candidate or to show that you are more knowledgeable then just stop and leave the room. You are not doing anyone any service with that ego/attitude and you are wasting time - candidate and yours.

Is mentioning this even necessary? I've either seen or heard about such an experience so many times that I believe it is. Twice in my life I've even witnessed a worse situation; the decision to hire a candidate was made up the management chain but some other team with a bruised ego managed to organize an additional interview with a candidate just to prove that hiring decision was wrong.

Another important topic is to decide what kind of candidate you are looking for. It's worth remembering that unicorns exist only in fairy tales and if you are unable to fill the position for over a year maybe it's time to reconsider a profile or your approach. This is especially true in situations where you are looking for a person with knowledge about some very niche or obscure technology. Most of such things can be learned and it's more important to hire someone with good fundamental knowledge rather than someone with 5 years of experience of technology that was invented last year by you and your friends.

## Structure of the interview

Important thing to remember is that we all have our biases. You might be aware of them or not but it does not matter as they will impact your judgment either way. It is therefore vital to have at least two or more people engaged in the process of interviewing a given candidate. Ideally such interviews should be conducted separately so the chances of reinforcing a bias are reduced. Regardless whether it is only you or a group, always try to justify your decision in writing. Inability to produce written arguments for or against a given candidate is a sure sign that you should reconsider your position.

Hotly debated topic is usually how many interviews should be conducted. Doing just one might not paint the fair picture. On the other hand dragging someone through endless rounds and constantly scheduling new sessions to assess yet another area will most likely result in candidates bailing out or being rejected for no good reason. In my personal experience a phone call interview followed up by a series of 4 or 5 on-site ones tend to yield fairly good and objective results. I do not recall a single case where scheduling a follow-up interview led to change of the initial decision.

Initial phone call serve to assess if inviting candidates for an on-site interview is a good investment. Such a call should not be focused on one topic but should rather comprehensively assess the candidate profile. On-site interview is a different beast - before the pandemic it involved flying candidates to a location and engaging few engineers to conduct the interview, write feedback and finally decide if a candidate should be offered a job. Nowadays it is usually conducted over the video conference but the time investment remains roughly the same. It is important to make the best use of it.

## Technical questions

I would like to begin discussion about the actual interview by enumerating certain bad practices I've seen over the years. My hope is that all the people reading this article will steer clear of them in the future.

**Asking for things not in CV.** When I am tasked with assessing the candidate, reading the CV is the first thing I do. That gives me a good idea of what to expect and I never ask about things I haven't seen in the CV. Why would you quiz the candidate about ARM assembly or low level exploitation if the CV clearly tells you that the given person is a web security expert and doesn't even mention C? Questions like that serve only to stroke the ego of the interviewer. On the other hand - whatever you put in the CV is fair game. Don't act surprised having to answer questions about debugging if you put a *Reverse Engineering Expert* there.

**Trick/Gotcha questions.** I absolutely hate questions that rely on having some piece of arcane or terribly specific knowledge and you can't even begin to answer or reason about without it. It's great that you know that Linux kernel pre-3.4 allows the allocation of memory pages at address 0 and that makes exploiting NULL pointer dereference possible in certain situations, but please, don't expect other people to know that as well. What is more, do not give candidates negative points for it as such a gap in knowledge tells you exactly nothing.

**(Implementation) details.** Please give my exact definition of vulnerability X. Please tell me exactly how library Y implements algorithm Z. I've seen questions like that many times and the people who ask such questions usually expect answers given to the letter. Again, failure to answer such a question to the satisfaction of the interviewer tells you exactly nothing. Exact definitions are worthless and implementation details will change over time. It is way more important if the candidate understands the topic rather than can recite some magic formula. Once I had a candidate who could recite a definition of every vulnerability from the Web Application Hacker's Handbook but was unable to give a single example of a vulnerable code pattern for a named vulnerability.

Moving forward I would like to focus on the approaches I've used over the years. There are several rules I try to follow and they generated fairly good interviewing experiences. I wasn't the one who invented all of them as I always try to incorporate positive elements of the interviews I was the subject of.

**Ask questions you already know the answer to.** I come prepared for every interview I do. I have a set of questions tailored for a candidate. I know how much time I have for every one of them. I roughly know what I would like to hear and I know the topic I'm asking for very well so I can freely steer the conversation. It's pretty embarrassing when a candidate is answering your question and you don't even know if it makes any sense or how to suggest a proper path without burning the whole question. Single lesson here is to be prepared. 

**Ask fundamental questions.** I try not to chase the latest hotness in the security world. It's great that you've read the writeup of the latest Nginx vulnerability but if the candidate did not there won't be a common ground for a question. Effect being you will most likely use 15 minutes of your time just explaining the basics of it. My advice is to stick to fundamental questions - how a major building block of a given field works. For web security people - CORS or even SOP (as an example). Candidates able to explain something like that clearly and concisely send far stronger signals than someone who happened to have read the same blog post.

**How would you do it?** Inevitably there will come a situation when a candidate won't be able to answer a question you've just asked. I personally love those moments because that leads to my favorite type of question - how would you implement it then? Such a question can really show how a candidate thinks and what he/she understands from a given problem.

**Support candidate**. There are different schools of grilling a candidate. Some people remain silent and offer no help and there are others who practically answer the question for them. Be somewhere in the middle - offer help and hints when a candidate is stuck. Interviews are stressful situations with additional pressure of time so it's natural that candidates will either forget some detail, mix something or be stuck on a certain piece of the answer. Offering some help might relax the candidate and produce a better outcome.

**Don't ask questions like everybody else.** Typical pattern for security questions is to ask candidates about some type of vulnerability. Questions focus on how it works and how it can be exploited. There is no reason to stop there. Chances are that you are not recruiting for a purely offensive role. In my role it's more important to be able to spot the coding pattern that might lead to a certain vulnerability or to be able to design a mitigation preventing such vulnerability at scale. Some people might even ask how to automate detecting such vulnerability. An open position should dictate the path you should take with such questions.

**Problem solving questions are good**. Most of the people can learn to recite definitions of vulnerabilities or even tell you how to mitigate them. If you really want to test the candidate, give a problem to solve. You say you are great in low level exploitation? Here is the list of gadgets in the program - make me a ROP chain.

## Coding

As I've previously mentioned I don't have much of an experience interviewing software engineers therefore don't expect eulogy about inverting binary trees. Still, sometimes we need to ask the coding questions. Most of the time they are relatively simple but the whiteboard coding is controversial enough to warrant a few words about it.

First of all, you need to think about the level of the questions. In general a purely algorithmic question might be a good match for a fresh graduate but a system design question might be better suited for a more senior person. In security roles there is generally no need to ask very complicated coding questions.

I usually allow candidates to pick their favorite language but I reserve the right to overrule it in case there is a chance I might not be familiar with it. All Haskell aficionados are kindly requested to rather stick to python. There were moments where I specifically asked for a piece of code in C where using python would just spoil the fun - especially for some very low level types of tasks (like moving pointers).

During the coding session I always act as a virtual editor - I flag syntax errors and if asked I correct system/library calls. Rationale behind it is simple - in every normal situation except maybe being stuck on ISS such tools would be at candidate disposal and there is no need to introduce additional difficulty.

When the candidate creates a solution it is usually a good idea to iterate over it to produce better final outcome - such exercise can tell a lot about a candidate as spotting and correcting own mistakes is often in short supply among the crowd.

In general I tend to give points first of all for solving the problem but also for clean and readable code as well as for using the language specific constructs. You don't get many if you write your Python like C without types.

## Closing words

Interviewing is hard. Candidate suffers through stress and anxiety to get to the place where you already comfortably sit. One thing we own them is to make this whole experience as good as possible for them. Even if the candidate gets rejected their experience should be about seeing the room for improvement and learning a lot through the questions.

We've mostly focused on technical questions here but there is one rule I've left for the end - keep the assholes out. It does not matter if the candidate answered all the technical questions correctly. In case of an unchecked ego or toxic personality you will be better off without a strong candidate rather than having your team destroyed by such an individual.