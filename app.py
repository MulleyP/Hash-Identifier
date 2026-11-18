
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from hash_tool import (
    identify_hash,
    calculate_file_hash,
    compare_hashes
)


# Main application window
root = tk.Tk()

root.title("Hash Identifier Pro")
root.geometry("750x650")
root.minsize(650, 550)


# Application styling
style = ttk.Style()

style.theme_use("clam")

style.configure(
    "TButton",
    padding=8
)

style.configure(
    "TLabel",
    padding=4
)


# Main heading
title = ttk.Label(
    root,
    text="HASH IDENTIFIER PRO",
    font=("Arial", 20, "bold")
)

title.pack(pady=15)


subtitle = ttk.Label(
    root,
    text="Cybersecurity Hash Analysis & File Integrity Tool"
)

subtitle.pack(pady=5)


# Create tabs
notebook = ttk.Notebook(root)

notebook.pack(
    fill="both",
    expand=True,
    padx=15,
    pady=15
)


#tab 1: Hash Identifier

identify_tab = ttk.Frame(notebook)

notebook.add(identify_tab, text="Hash Identifier")


ttk.Label(
    identify_tab,
    text="Enter a hash value:",
    font=("Arial", 12, "bold")
).pack(anchor="w", padx=15, pady=10)


hash_entry = ttk.Entry(
    identify_tab,
    width=75
)

hash_entry.pack(padx=15, fill="x")


result_box = tk.Text(
    identify_tab,
    height=12,
    width=75,
    state="disabled"
)

result_box.pack(
    padx=15,
    pady=15,
    fill="both",
    expand=True
)


def run_identification():

    value = hash_entry.get()

    result = identify_hash(value)

    output = []

    output.append("HASH ANALYSIS RESULTS")
    output.append("-" * 35)

    output.append(f"Input length: {result['length']}")
    output.append(f"Format: {result['format']}")
    output.append(f"Status: {result['status']}")

    output.append("")

    if result["candidates"]:

        output.append("Possible algorithms:")

        for algorithm in result["candidates"]:
            output.append(f"- {algorithm}")

    else:
        output.append("No matching algorithms found.")

    result_box.config(state="normal")

    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        "\n".join(output)
    )

    result_box.config(state="disabled")


ttk.Button(
    identify_tab,
    text="Identify Hash",
    command=run_identification
).pack(pady=10)

#tab 2: File Hasher


file_tab = ttk.Frame(notebook)

notebook.add(file_tab, text="File Hasher")


selected_file = tk.StringVar()

algorithm_choice = tk.StringVar(
    value="sha256"
)


def select_file():

    filename = filedialog.askopenfilename()

    if filename:
        selected_file.set(filename)


ttk.Label(
    file_tab,
    text="Select a file to calculate its hash:",
    font=("Arial", 12, "bold")
).pack(anchor="w", padx=15, pady=15)


ttk.Entry(
    file_tab,
    textvariable=selected_file,
    width=65
).pack(padx=15, fill="x")


ttk.Button(
    file_tab,
    text="Browse Files",
    command=select_file
).pack(pady=10)


ttk.Label(
    file_tab,
    text="Select hashing algorithm:"
).pack(pady=5)


algorithm_dropdown = ttk.Combobox(
    file_tab,
    textvariable=algorithm_choice,
    values=[
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512"
    ],
    state="readonly"
)

algorithm_dropdown.pack(pady=5)


file_result = tk.Text(
    file_tab,
    height=8,
    width=75,
    state="disabled"
)

file_result.pack(
    padx=15,
    pady=15,
    fill="both",
    expand=True
)


def generate_file_hash():

    filename = selected_file.get()

    if not filename:
        messagebox.showwarning(
            "Missing File",
            "Please select a file first."
        )
        return

    try:

        algorithm = algorithm_choice.get()

        result = calculate_file_hash(
            filename,
            algorithm
        )

        output = (
            f"File: {filename}\n"
            f"Algorithm: {algorithm.upper()}\n\n"
            f"Generated Hash:\n{result}"
        )

        file_result.config(state="normal")

        file_result.delete("1.0", tk.END)

        file_result.insert(tk.END, output)

        file_result.config(state="disabled")

    except (ValueError, FileNotFoundError, OSError) as error:

        messagebox.showerror(
            "Error",
            str(error)
        )


ttk.Button(
    file_tab,
    text="Generate File Hash",
    command=generate_file_hash
).pack(pady=10)


# ==================================
# TAB 3: HASH COMPARISON
# ==================================

compare_tab = ttk.Frame(notebook)

notebook.add(compare_tab, text="Hash Comparison")


ttk.Label(
    compare_tab,
    text="Enter first hash:"
).pack(anchor="w", padx=15, pady=10)


first_hash = ttk.Entry(
    compare_tab,
    width=75
)

first_hash.pack(padx=15, fill="x")


ttk.Label(
    compare_tab,
    text="Enter second hash:"
).pack(anchor="w", padx=15, pady=10)


second_hash = ttk.Entry(
    compare_tab,
    width=75
)

second_hash.pack(padx=15, fill="x")


comparison_result = ttk.Label(
    compare_tab,
    text="",
    font=("Arial", 12, "bold")
)

comparison_result.pack(pady=30)


def run_comparison():

    try:

        result = compare_hashes(
            first_hash.get(),
            second_hash.get()
        )

        if result:

            comparison_result.config(
                text="MATCH: Hashes are identical.",
                foreground="green"
            )

        else:

            comparison_result.config(
                text="NO MATCH: Hashes are different.",
                foreground="red"
            )

    except ValueError as error:

        messagebox.showerror(
            "Input Error",
            str(error)
        )


ttk.Button(
    compare_tab,
    text="Compare Hashes",
    command=run_comparison
).pack(pady=10)

print("Hash Identifier Pro is starting...")
# Start application
root.mainloop()
