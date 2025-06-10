Summary:
1. For this challenge, we have to interact with their official Discord Server's bot named `john`
2. Running `!flag` will only give us a fake flag, but we can ask john for his story using `part0` to `part 4`
3. This is the pieced together story of john ```
The hacker-name-John was well known in the underground
He was known-for-his-skills and could solve even the-toughest-challenges
Late one night. He began-working on a new challenge.
It seemed easy at first. but there was more than met the eye. He tried.
He focused. He concentrated. He adapted. He started-seeing-patterns that others missed
He is good. He recognized these hidden clues. With each-clue, his-understanding deepened. His-dedication was unwavering
John could feel the pressure.He struggled. can crack-this, he thought
Time was running-out, but he stayed calm.
Every keystroke mattered. He waited. He was almost at the end. Happiness-was filled
Finally. the last piece of the challenge was in place. Success was his. and he-couldn't help-but smile
The breakthrough had come at last. after-long-hours-of-perseverance
His dedication had paid off. Every-detail every clue. that had led to this moment.
He admired. his work with a sense of accomplishment. The hacker-name-John had done it again. solving-the unsolvable
He knew this victory was just one of many-to-come, and with that thought. He prepared. He awaited for his next challenge.
As dawn broke. John-reflected on the journey.
Each challenge had sharpened his skills. In each victory. He had strengthened his-resolve
He looked-forward to new-challenge. New mysteries to unravel. New challenges.
The world of hacking was full of secret.He was confident. He believed. He was ready to uncover them all.```
4. There is already something suspicious here, there are dots and dashes weirdly and randomly placed in between words of the sentences. These are morse code.
5. Extract the dots and dashes from the story, treating `\n` characters as a boundary for each letter of the morse code. In my case I used this script: ```
```python
whole = ""
with open("story.txt", "r") as f:
	line = f.read()
	lines = line.split('\n')

	for line in lines:
		symbol = ""
		
		for c in line:
			if c in ".-":
			symbol += c
		
		whole += symbol + ' '

print(whole)
```
6. The extracted morse code is ```
-- ----- .-. ... ...-- ..--.- ..- -. ...- ...-- .---- .-.. ..--.- --... .-. ..- --... ....```

7. The decoded message is `M0RS3_UNV31L_7RU7H`
8. Flag: `ironCTF{M0RS3_UNV31L_7RU7H}`