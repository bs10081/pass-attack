import itertools
import multiprocessing
import time
import sys
import os
from PyPDF2 import PdfReader
import tkinter as tk
from tkinter import filedialog
from tqdm import tqdm
import queue
import argparse
from multiprocessing import Process, Queue, Event, Value
import ctypes
import math
import psutil

def select_pdf_file():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename(
        title="選擇加密的 PDF 文件",
        filetypes=[("PDF 文件", "*.pdf"), ("所有文件", "*.*")]
    )

def check_pdf_password(pdf_path, password):
    try:
        reader = PdfReader(pdf_path, password=password)
        return reader.is_encrypted and len(reader.pages) > 0
    except Exception:
        return False

class SharedCounter(object):
    def __init__(self, init_val=0):
        self.val = Value(ctypes.c_long, init_val)

    def increment(self, n=1):
        with self.val.get_lock():
            self.val.value += n

    @property
    def value(self):
        return self.val.value

def worker_process(task_queue, result_queue, pdf_path, prefix, stop_event, progress_counter):
    local_counter = 0
    update_threshold = 5000
    
    while not stop_event.is_set():
        try:
            start_num, batch_size = task_queue.get_nowait()
        except queue.Empty:
            break

        for i in range(start_num, start_num + batch_size):
            if stop_event.is_set():
                break
            
            password = f"{prefix}{i:0{10-len(prefix)}d}"
            if check_pdf_password(pdf_path, password):
                result_queue.put(("success", password))
                stop_event.set()
                return

            local_counter += 1
            if local_counter >= update_threshold:
                progress_counter.increment(local_counter)
                result_queue.put(("progress", local_counter))
                local_counter = 0

    if local_counter > 0:
        progress_counter.increment(local_counter)
        result_queue.put(("progress", local_counter))

def calculate_optimal_batch_size(total_combinations, num_processes):
    # 根據總組合數動態調整批次大小
    if total_combinations <= 100000:
        base_batch_size = 1000
    elif total_combinations <= 1000000:
        base_batch_size = 10000
    elif total_combinations <= 10000000:
        base_batch_size = 50000
    else:
        base_batch_size = 100000
    
    # 確保每個進程至少有幾個批次要處理，避免任務分配不均
    optimal_batch_size = min(base_batch_size, total_combinations // (num_processes * 4))
    
    # 確保批次大小不小於最小值
    return max(1000, optimal_batch_size)


def process_manager(num_processes, total_combinations, batch_size, pdf_path, prefix):
    task_queue = Queue()
    result_queue = Queue()
    stop_event = Event()
    progress_counter = SharedCounter(0)

    num_batches = math.ceil(total_combinations / batch_size)
    for i in range(num_batches):
        start = i * batch_size
        current_batch_size = min(batch_size, total_combinations - start)
        task_queue.put((start, current_batch_size))

    pbar = tqdm(total=total_combinations, desc="破解進度", unit="組合", smoothing=0.1)
    last_progress = 0

    processes = []
    for _ in range(num_processes):
        p = Process(target=worker_process, 
                   args=(task_queue, result_queue, pdf_path, prefix, stop_event, progress_counter))
        processes.append(p)
        p.start()

    start_time = time.time()
    success_password = None
    
    try:
        while any(p.is_alive() for p in processes):
            try:
                msg_type, data = result_queue.get(timeout=0.1)
                if msg_type == "success":
                    success_password = data
                    stop_event.set()
                    break
                elif msg_type == "progress":
                    current_progress = progress_counter.value
                    if current_progress > last_progress:
                        pbar.update(current_progress - last_progress)
                        last_progress = current_progress
            except queue.Empty:
                continue

            pbar.refresh()

    except KeyboardInterrupt:
        print("\n\nINFO 使用者中斷程式執行")
        stop_event.set()

    finally:
        for p in processes:
            p.join()
        
        final_progress = progress_counter.value
        if final_progress > last_progress:
            pbar.update(final_progress - last_progress)
        
        pbar.close()
        end_time = time.time()
        total_time = end_time - start_time

        if success_password:
            print(f"\nINFO 破解成功！PDF 密碼是：{success_password}")
        print(f"INFO 總耗時：{total_time:.2f} 秒")
        print(f"INFO 總共嘗試：{progress_counter.value:,} 組合")
        print(f"INFO 平均速度：{progress_counter.value / total_time:.2f} 組合/秒")

def crack_pdf(pdf_path, prefix, num_processes=None, batch_size=None):
    remaining_digits = 10 - len(prefix)
    total_combinations = 10**remaining_digits
    
    # 固定使用 CPU 邏輯核心數的兩倍作為進程數
    if num_processes is None:
        num_processes = psutil.cpu_count(logical=True) * 2
    
    if batch_size is None:
        batch_size = calculate_optimal_batch_size(total_combinations, num_processes)
    
    print(f"\nINFO 開始破解 PDF 文件")
    print(f"INFO 使用 {num_processes} 個進程 (CPU 邏輯核心數的兩倍)")
    print(f"INFO 每批次處理 {batch_size:,} 個密碼組合")
    print(f"INFO 目標文件: {pdf_path}")
    print(f"INFO 前綴: {prefix}")
    print(f"INFO 總組合數: {total_combinations:,}")

    process_manager(num_processes, total_combinations, batch_size, pdf_path, prefix)

def main():
    parser = argparse.ArgumentParser(description='PDF 密碼破解工具 v1.6')
    parser.add_argument('-f', '--file', help='PDF 文件路徑')
    parser.add_argument('-p', '--prefix', help='身分證前綴(至少兩位，例如地區+性別)')
    parser.add_argument('--cli', action='store_true', help='使用命令列介面模式')
    parser.add_argument('--processes', type=int, help='使用的進程數量')
    parser.add_argument('--batch-size', type=int, help='每批次處理的密碼數量')
    args = parser.parse_args()

    if args.cli:
        pdf_path = args.file
        prefix = args.prefix
    else:
        if not args.file:
            pdf_path = select_pdf_file()
        else:
            pdf_path = args.file

        if not args.prefix:
            prefix = input("請輸入身分證前綴（至少兩位，例如地區+性別）：")
        else:
            prefix = args.prefix

    if not pdf_path or not os.path.exists(pdf_path):
        print("錯誤：PDF 文件不存在")
        return

    if len(prefix) < 2:
        print("錯誤：前綴至少需要兩位")
        return

    crack_pdf(pdf_path, prefix, num_processes=args.processes, batch_size=args.batch_size)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
