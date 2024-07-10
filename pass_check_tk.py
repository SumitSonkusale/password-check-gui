import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength(password):
    # Define the criteria for a strong password
    length_criteria = len(password) >= 8
    digit_criteria = re.search(r"\d", password) is not None
    uppercase_criteria = re.search(r"[A-Z]", password) is not None
    lowercase_criteria = re.search(r"[a-z]", password) is not None
    special_char_criteria = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None
    
    # Calculate strength score
    strength_score = sum([length_criteria, digit_criteria, uppercase_criteria, lowercase_criteria, special_char_criteria])
    
    # Determine strength level
    if strength_score == 5:
        strength = "Very Strong"
    elif strength_score == 4:
        strength = "Strong"
    elif strength_score == 3:
        strength = "Moderate"
    elif strength_score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    # Provide detailed feedback
    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not digit_criteria:
        feedback.append("Password should include at least one digit (0-9).")
    if not uppercase_criteria:
        feedback.append("Password should include at least one uppercase letter (A-Z).")
    if not lowercase_criteria:
        feedback.append("Password should include at least one lowercase letter (a-z).")
    if not special_char_criteria:
        feedback.append("Password should include at least one special character (e.g., !@#$%^&*).")
    
    return strength, feedback

def check_password():
    password = password_entry.get()
    strength, feedback = check_password_strength(password)
    result_label.config(text=f"Password strength: {strength}")
    
    if feedback:
        messagebox.showinfo("Password Feedback", "\n".join(feedback))

def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")

# Create and place the widgets
tk.Label(root, text="Enter a password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=0, column=1, padx=10, pady=10)

# Create the "Show Password" checkbox
show_password_var = tk.BooleanVar()
show_password_checkbutton = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbutton.grid(row=0, column=2, padx=10, pady=10)

tk.Button(root, text="Check Strength", command=check_password).grid(row=1, columnspan=3, pady=10)
result_label = tk.Label(root, text="")
result_label.grid(row=2, columnspan=3, pady=10)

# Start the main event loop
root.mainloop()
