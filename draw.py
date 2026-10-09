import random

def secret_santa_draw(participants):
    givers = participants.copy()
    receivers = participants.copy()
    
    while True:
        random.shuffle(receivers)
        if all(g != r for g, r in zip(givers, receivers)):
            break
            
    print("🎅 Жеребьевка успешно завершена!")
    print("-" * 40)
    for giver, receiver in zip(givers, receivers):
        print(f"🎁 {giver}  --->  {receiver}")
    print("-" * 40)

if __name__ == "__main__":
    team = ["Участник 1", "Участник 2", "Участник 3", "Участник 4", 
            "Участник 5", "Участник 6", "Участник 7", "Участник 8", "Участник 9"]
    secret_santa_draw(team)
